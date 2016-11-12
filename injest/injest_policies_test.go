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

func TestInjestPolicies(t *testing.T) {
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

	Convey("Injest policies", t, func() {
		Convey("Remove all policies if section is present and empty", nil)
		Convey("A policy is modified if differs", func() {

			originalSecretPolicies := `path "secret/*" { policy = "write" }`
			modifiedSecretPolicies := `path "secret/*" { policy = "read" }`

			policies := vaultConfig{
				Policies: []policyDefiniton{
					policyDefiniton{
						Name:  "root",
						Rules: "${ignore}",
					},
					policyDefiniton{
						Name:  "default",
						Rules: "${ignore}",
					},
					policyDefiniton{
						Name:  "response-wrapping",
						Rules: "${ignore}",
					},
					policyDefiniton{
						Name:  "secret",
						Rules: originalSecretPolicies,
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			policiesList, err := vault.ListPolicies()
			So(err, ShouldBeNil)

			secretPolicy, ok := (*policiesList)["secret"]
			So(ok, ShouldBeTrue)
			So(secretPolicy.Rules, ShouldEqual, originalSecretPolicies)

			log.Debug("########## Reapplying modified policies")

			policies = vaultConfig{
				Policies: []policyDefiniton{
					policyDefiniton{
						Name:  "root",
						Rules: "${ignore}",
					},
					policyDefiniton{
						Name:  "default",
						Rules: "${ignore}",
					},
					policyDefiniton{
						Name:  "response-wrapping",
						Rules: "${ignore}",
					},
					policyDefiniton{
						Name:  "secret",
						Rules: modifiedSecretPolicies,
					},
				},
			}
			err = injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			policiesList, err = vault.ListPolicies()
			So(err, ShouldBeNil)

			secretPolicy, ok = (*policiesList)["secret"]
			So(ok, ShouldBeTrue)
			So(secretPolicy.Rules, ShouldEqual, modifiedSecretPolicies)
		})
	})
}
