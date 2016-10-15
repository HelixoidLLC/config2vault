// +build integration
/*
 * Copyright 2016 Igor Moochnick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package injest

import (
	"config2vault/log"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestInjestConsulBackend(t *testing.T) {
	t.Skip("skipping test for now.")

	log.SetLevel(log.ErrorLevel)

	vault, key, deferFn, err := createTestProject("../testing/integration/consul/docker-compose.yml", "", "", "", nil, false)
	if deferFn != nil {
		defer deferFn()
	}
	if err != nil {
		t.Fatal("Failed to initialize Vault client")
	}
	if key == "" {
		t.Fatal("Got an Empty security key")
	}

	Convey("Consul injest", t, func() {
		Convey("Role is created", func() {
			mountType := "consul"
			mountPath := "consul"
			mountDescr := "Consul backend"
			policies := vaultConfig{
				Mounts: []mountInfo{
					mountInfo{
						Path:               mountPath,
						Type:               mountType,
						Description:        mountDescr,
						PolicyBase64Encode: true,
						Config: []map[string]interface{}{
							{
								"path": "access",
								"properties": map[string]string{
									"address": "consul00.consul:8500",
									"token":   "a49e7360-f150-463a-9a29-3eb186ffae1a",
								},
							},
						},
					},
				},
				Roles: []rolePolicy{
					{
						Name: "readonly",
						Path: mountPath,
						Properties: map[string]string{
							//"policy": `key "" {
							//		policy = "read"
							//	}`,
							"policy": `key "" { policy = "read" }`,
						},
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeEmpty)

			mounts, err := vault.ListMounts()
			if err != nil {
				t.Fatal("Failed to get mounts")
			}
			consulMount := (*mounts)[mountPath]

			So(consulMount, ShouldNotBeNil)
			So(consulMount.Description, ShouldEqual, mountDescr)

			time.Sleep(2 * time.Second) // TODO: flapping test. Vault needs to dijest the policy request

			// TODO: read and validate policy from Consul because currently Vault doesn't return back a list of configured roles

			secret, err := vault.Client.Logical().Read("consul/creds/readonly")
			if err != nil {
				t.Fatalf("Failed to generate new Consul ACL token. %#v", err)
			}
			log.Infof("Got secret: %#v", *secret)

			token := getStringFromMap(&secret.Data, "token", "")
			So(token, ShouldNotBeEmpty)
		})
	})
}
