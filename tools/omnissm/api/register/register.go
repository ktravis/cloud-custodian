/*
Copyright 2018 Capital One Services, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

const (
	// SSMInstanceRole IAM Role to associate to instance registration
	SSMInstanceRole = "service-role/AmazonEC2RunCommandRoleForManagedInstances"

	// AWSRSAIdentityCert is the RSA public certificate
	AWSRSAIdentityCert = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`

	GCPCertAddress = "https://www.googleapis.com/oauth2/v1/certs"

	ProviderAWS = "aws"
	ProviderGCP = "gcp"
)

var (
	// RSACert AWS Public Certificate
	AWSRSACert *x509.Certificate
	// RSACertPEM Decoded pem signature
	AWSRSACertPEM, _ = pem.Decode([]byte(AWSRSAIdentityCert))

	GCPPubKeys = make(map[string]*rsa.PublicKey)

	dbClient  *dynamodb.DynamoDB
	ssmClient *ssm.SSM

	Region = os.Getenv("AWS_REGION")

	// RegistrationTable DynamodDb Table for storing instance regisrations
	RegistrationTable = os.Getenv("REGISTRATION_TABLE")

	// Only allow instance registrations from these accounts, read from
	// $ACCOUNT_WHITELIST (comma-separated)
	accountWhitelist = make(map[string]bool)
)

func init() {
	var err error

	// Parse AWS public certificate
	if AWSRSACert, err = x509.ParseCertificate(AWSRSACertPEM.Bytes); err != nil {
		panic(err)
	}

	// Acquire GCP public certificates, which rotate daily
	resp, err := http.Get(GCPCertAddress)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("unexpected response from google cert endpoint: %s", string(b))
	}

	var keys map[string]string

	if err := json.Unmarshal(b, &keys); err != nil {
		log.Fatal(err)
	}

	// Populate RSA public key map
	for k, v := range keys {
		pub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(v))
		if err != nil {
			log.Fatal(err)
		}
		GCPPubKeys[k] = pub
	}

	cfg, err := external.LoadDefaultAWSConfig()
	if err != nil {
		panic("unable to load SDK config, " + err.Error())
	}

	dbClient = dynamodb.New(cfg)
	ssmClient = ssm.New(cfg)

	w := os.Getenv("ACCOUNT_WHITELIST")
	for _, a := range strings.Split(w, ",") {
		accountWhitelist[a] = true
	}
}

type InstanceIdentity interface {
	Provider() string
	Identifier() string
}

type GCPInstanceIdentity struct {
	ProjectID                 string `json:"project_id"`
	ProjectNumber             uint   `json:"project_number"`
	Zone                      string `json:"zone"`
	InstanceID                string `json:"instance_id"`
	InstanceName              string `json:"instance_name"`
	InstanceCreationTimestamp uint   `json:"instance_creation_timestamp"`
}

func (GCPInstanceIdentity) Provider() string { return ProviderGCP }

func (i GCPInstanceIdentity) Identifier() string {
	return fmt.Sprintf("%d-%s", i.ProjectNumber, i.InstanceID)
}

// InstanceIdentity provides for ec2 metadata instance information
type AWSInstanceIdentity struct {
	ManagedID        string `json:"managedId"`
	AvailabilityZone string `json:"availabilityZone"`
	Region           string `json:"region"`
	InstanceID       string `json:"instanceId"`
	AccountID        string `json:"accountId"`
	InstanceType     string `json:"instanceType"`
}

func (AWSInstanceIdentity) Provider() string { return ProviderAWS }

// Identifier Get a unique identifier for an instance
func (i AWSInstanceIdentity) Identifier() string {
	return strings.Join([]string{i.AccountID, i.InstanceID}, "-")
}

func idHash(ident string) string {
	h := sha1.New()
	h.Write([]byte(ident))
	bid := h.Sum(nil)
	return fmt.Sprintf("%x", bid)
}

// InstanceRegistration Minimal
type InstanceRegistration struct {
	ID             string `json:"id"`
	ActivationCode string
	ActivationID   string `json:"ActivationId"`
	ManagedID      string `json:"ManagedId"`
}

// GetRegistration fetch instance registration from db
func GetRegistration(id string) (*InstanceRegistration, error) {
	params := &dynamodb.GetItemInput{
		TableName: aws.String(RegistrationTable),
		AttributesToGet: []string{
			"id", "ActivationId", "ActivationCode", "ManagedID",
		},
		Key: map[string]dynamodb.AttributeValue{
			"id": {
				S: aws.String(id),
			},
		},
	}

	req := dbClient.GetItemRequest(params)
	resp, err := req.Send()
	if err != nil {
		return nil, err
	}
	var r InstanceRegistration
	if err := dynamodbattribute.UnmarshalMap(resp.Item, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RegisterInstance Create SSM activation for instance and store
func RegisterInstance(id string) (*InstanceRegistration, error) {
	activateReq := ssmClient.CreateActivationRequest(&ssm.CreateActivationInput{
		DefaultInstanceName: aws.String(id),
		Description:         aws.String(id),
		IamRole:             aws.String(SSMInstanceRole),
	})
	resp, err := activateReq.Send()
	if err != nil {
		return nil, err
	}

	r := &InstanceRegistration{
		ID:             idHash(id),
		ActivationCode: *resp.ActivationCode,
		ActivationID:   *resp.ActivationId,
	}
	item, err := dynamodbattribute.MarshalMap(r)
	if err != nil {
		return nil, errors.Wrap(err, "registration item could not be marshaled")
	}
	insertParams := &dynamodb.PutItemInput{
		Item:      item,
		TableName: aws.String(RegistrationTable),
	}

	insertRequest := dbClient.PutItemRequest(insertParams)
	if resp, err := insertRequest.Send(); err != nil {
		return nil, errors.Wrapf(err, "Put Registration failed (%v)", resp)
	}
	return r, nil
}

// UpdateManagedID Record SSM Managed ID for an Instance
func UpdateManagedID(id string, managedID string) error {
	params := &dynamodb.UpdateItemInput{
		TableName: aws.String(RegistrationTable),
		Key: map[string]dynamodb.AttributeValue{
			"id": dynamodb.AttributeValue{
				S: aws.String(id),
			},
		},
		UpdateExpression: aws.String("SET ManagedId = :mid"),
		ExpressionAttributeValues: map[string]dynamodb.AttributeValue{
			":mid": {
				S: aws.String(managedID),
			},
		},
	}

	req := dbClient.UpdateItemRequest(params)
	if _, err := req.Send(); err != nil {
		return err
	}
	return nil
}

// RegistrationRequest structure of instance registration request
type RegistrationRequest struct {
	Identity  string `json:"identity"`
	Signature string `json:"signature"`
	Provider  string `json:"provider"`
	ManagedID string `json:"managed-id"`
}

func (r *RegistrationRequest) Validate() (InstanceIdentity, events.APIGatewayProxyResponse) {
	// TODO: At the moment this is AWS Specific, support GCP & Azure to the extant possible.
	switch r.Provider {
	case ProviderAWS:
		signature, err := base64.StdEncoding.DecodeString(r.Signature)
		if err != nil {
			return nil, newErrorResponse("invalid-request", "malformed rsa signature", 400)
		}
		err = AWSRSACert.CheckSignature(x509.SHA256WithRSA, []byte(r.Identity), signature)
		if err != nil {
			return nil, newErrorResponse("invalid-signature", "invalid identity", 400)
		}

		var i AWSInstanceIdentity
		// We verified the signature, so malformed here would more than odd.
		_ = json.Unmarshal([]byte(r.Identity), &i)

		// Capture request variable into identity
		i.ManagedID = r.ManagedID

		return i, events.APIGatewayProxyResponse{}
	case ProviderGCP:
		p := &jwt.Parser{
			ValidMethods:  []string{"RS256"},
			UseJSONNumber: true,
		}
		var claims struct {
			jwt.StandardClaims
			Identity GCPInstanceIdentity `json:"google"`
		}
		// r.Signature is the signed JWT returned by the GCP instance
		// metadata service, which contains the identity document
		_, err := p.ParseWithClaims(r.Signature, &claims, func(t *jwt.Token) (interface{}, error) {
			kid, ok := t.Header["kid"].(string)
			if !ok {
				return nil, errors.Errorf("unexpected kid in token header: %v", t.Header["kid"])
			}

			key, ok := GCPPubKeys[kid]
			if !ok {
				return nil, errors.Errorf("invalid key id: %s", kid)
			}
			return key, nil
		})
		if err != nil {
			return nil, newErrorResponse("invalid-request", err.Error(), 400)
		}
		return claims.Identity, events.APIGatewayProxyResponse{}
	default:
		return nil, newErrorResponse("invalid-request", "unknown provider", 400)
	}
}

func handleRegister(i InstanceIdentity) events.APIGatewayProxyResponse {
	fmt.Printf("Instance Registration Request: %+v\n", i)

	id := i.Identifier()
	reg, err := GetRegistration(id)
	if err != nil {
		panic(err)
	}

	fmt.Println("Queried Instance", reg)
	if len(reg.ActivationCode) < 1 {
		reg, err = RegisterInstance(id)
		if err != nil {
			panic(err)
		}
	}

	response := map[string]interface{}{
		//"instance-id":     identity.InstanceID,
		//"account-id":      identity.AccountID,
		"region":          Region,
		"activation-id":   reg.ActivationID,
		"activation-code": reg.ActivationCode,
	}

	serialized, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}
	fmt.Println("Register Response", string(serialized))
	return events.APIGatewayProxyResponse{Body: string(serialized), StatusCode: 200}
}

func handleUpdateManagedID(i InstanceIdentity, mid string) events.APIGatewayProxyResponse {
	fmt.Printf("Instance Update SSMID Request: %+v\n", i)

	id := i.Identifier()

	reg, err := GetRegistration(id)
	if err != nil {
		panic(err)
	}
	fmt.Println("Queried Instance", reg)

	//if identity.ManagedID != "" {
	UpdateManagedID(id, mid)
	//}

	response := map[string]interface{}{
		//"instance-id": identity.InstanceID,
		//"account-id":  identity.AccountID,
		"managed-id": mid,
		"identity":   i,
	}
	serialized, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}
	fmt.Println("Update ssmid response", string(serialized))
	return events.APIGatewayProxyResponse{Body: string(serialized), StatusCode: 200}
}

func newErrorResponse(name, msg string, statusCode int) events.APIGatewayProxyResponse {
	response := map[string]string{
		"error":   name,
		"message": msg,
	}
	body, _ := json.Marshal(response)
	return events.APIGatewayProxyResponse{Body: string(body), StatusCode: statusCode}
}

func ResourceAllowed(i InstanceIdentity) bool {
	switch t := i.(type) {
	case AWSInstanceIdentity:
		return accountWhitelist[t.AccountID]
	case GCPInstanceIdentity:
		return false // TODO
	default:
		return false
	}
}

func handleRequest(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	fmt.Printf("Processing request data for request %s.\n", request.RequestContext.RequestID)
	fmt.Printf("Body size = %d.\n", len(request.Body))

	var req RegistrationRequest
	err := json.Unmarshal([]byte(request.Body), &req)
	if err != nil {
		return newErrorResponse("invalid-request", "malformed json", 400), nil
	}

	i, errorResponse := req.Validate()
	if i == nil {
		return errorResponse, nil
	}

	if !ResourceAllowed(i) {
		// Account is not whitelisted, deny request
		fmt.Printf("Request from resourace '%+v' is not whitelisted.\n", i)
		return newErrorResponse("invalid-request", "invalid account", 401), nil
	}

	switch request.HTTPMethod {
	case "POST":
		return handleRegister(i), nil
	case "PATCH":
		return handleUpdateManagedID(i, req.ManagedID), nil
	default:
		return newErrorResponse("invalid-method", fmt.Sprintf("method not allowed: %s", request.HTTPMethod), 405), nil
	}
}

func main() {
	lambda.Start(handleRequest)
}
