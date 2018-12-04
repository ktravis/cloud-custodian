// Copyright 2018 Capital One Services, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/aws/ec2metadata"
	client "github.com/capitalone/cloud-custodian/tools/omnissm/pkg/omnissm/omnissmclient"
	"github.com/capitalone/cloud-custodian/tools/omnissm/pkg/servicectl"
)

var RegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "",
	Run: func(cmd *cobra.Command, args []string) {
		url := viper.GetString("register_endpoint")
		if url == "" {
			log.Fatal().Msg("registration url (OMNISSM_REGISTER_ENDPOINT) cannot be blank")
		}
		doc := string(ec2metadata.GetLocalInstanceDocument())
		signature := string(ec2metadata.GetLocalInstanceSignature())
		c, err := client.New(url, doc, signature)
		if err != nil {
			log.Fatal().Msgf("unable to initialize node: %v", err)
		}
		if c.Managed() {
			log.Info().Str("ManagedId", c.ManagedId).Msg("instance already registered")
			return
		}
		s, err := servicectl.New(client.AmazonSSMAgentServiceName)
		if err != nil {
			log.Fatal().Msgf("cannot open service %#v: %v", client.AmazonSSMAgentServiceName, err)
		}
		log.Info().Str("Provider", c.Provider).Str("Document", doc).Str("ClientVersion", client.Version).Msg("attempting to register instance")
		if err := c.Register(); err != nil {
			log.Fatal().Msgf("cannot register instance: %v", err)
		}
		if err := c.Update(); err != nil {
			log.Fatal().Msgf("cannot update instance ManagedId: %v", err)
		}
		log.Info().Str("ManagedId", c.ManagedId).Msg("instance registered")
		if err := s.Restart(); err != nil {
			log.Fatal().Msgf("cannot restart service %#v: %v", client.AmazonSSMAgentServiceName, err)
		}
	},
}

func init() {
	RegisterCmd.Flags().String("register-endpoint", "", "")
	RegisterCmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		viper.BindPFlag(strings.Replace(f.Name, "-", "_", -1), RegisterCmd.Flags().Lookup(f.Name))
	})
}
