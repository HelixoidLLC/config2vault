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

	. "github.com/smartystreets/goconvey/convey"
)

func TestInjestGenericSecrets(t *testing.T) {
	t.Skip("skipping test for now.")

	log.SetLevel(log.ErrorLevel)

	testEnvPath := "../testing/integration/simple/docker-compose.yml"

	vault, key, deferFn, err := createTestProject(testEnvPath, "", "", "", nil, false)
	if deferFn != nil {
		defer deferFn()
	}
	if err != nil {
		t.Fatal("Failed to initialize Vault client")
	}
	if key == "" {
		t.Fatal("Got an Empty security key")
	}

	Convey("Generic Backend", t, func() {
		Convey("Secret is stored", func() {
			secretPath := "test/foo"
			policies := vaultConfig{
				Secrets: []genericSecret{
					genericSecret{
						Path: secretPath,
						Fields: []fieldPair{
							fieldPair{
								Key:   "zip",
								Value: "zap",
							},
						},
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeEmpty)

			secret, err := vault.Client.Logical().Read("/secret/" + secretPath)
			if err != nil {
				t.Fatalf("Failed to read secret. %#v", err)
			}
			log.Infof("Got secret: %#v", *secret)

			So(getStringFromMap(&secret.Data, "zip", ""), ShouldEqual, "zap")
		})
		Convey("Secret is removed if not on the list", func() {
			secretPath := "test/bar"
			policies := vaultConfig{
				Secrets: []genericSecret{
					genericSecret{
						Path: secretPath,
						Fields: []fieldPair{
							fieldPair{
								Key:   "zip",
								Value: "zap",
							},
						},
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeEmpty)

			secret, err := vault.Client.Logical().Read("/secret/" + secretPath)
			if err != nil {
				t.Fatalf("Failed to read secret. %#v", err)
			}
			log.Infof("Got secret: %#v", *secret)

			data := secret.Data
			So(data, ShouldNotBeNil)
			So(data, ShouldContainKey, "zip")
			So(data["zip"], ShouldEqual, "zap")

			vault.ListSecrets()

			log.Debug("#####################")

			policies = vaultConfig{
				Secrets: []genericSecret{},
			}
			err = injestConfig(vault, &policies)
			So(err, ShouldBeEmpty)

			secrets, err := vault.ListSecrets()
			So(err, ShouldBeEmpty)
			So(len(*secrets), ShouldBeZeroValue)

		})
	})
}
