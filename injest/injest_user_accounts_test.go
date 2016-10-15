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

func TestInjestUserAccounts(t *testing.T) {
	t.Skip("skipping test for now.")

	log.SetLevel(log.ErrorLevel)

	vault, key, deferFn, err := createTestProject("../testing/integration/simple/docker-compose.yml", "", "", "", nil, false)
	if deferFn != nil {
		defer deferFn()
	}
	if err != nil {
		t.Fatal("Failed to initialize Vault client")
	}
	if key == "" {
		t.Fatal("Got an Empty security key")
	}

	Convey("Injest user accounts", t, func() {
		Convey("Ask for Auth users to be mounted", func() {
			userName := "test"

			policies := vaultConfig{
				AuthBackends: []authBackendInfo{
					authBackendInfo{
						Type: "userpass",
					},
				},
				Users: []userAccount{
					userAccount{
						Name:     userName,
						Password: "secret",
						Policies: []string{
							"policy1",
						},
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			user, err := vault.GetUser(userName)
			So(err, ShouldBeNil)
			So(user.Name, ShouldEqual, userName)
			So(len(user.Policies), ShouldEqual, 2)
			So(user.Policies, ShouldContain, "default")
			So(user.Policies, ShouldContain, "policy1")

			log.Debug("***************************************")

			policies = vaultConfig{
				AuthBackends: []authBackendInfo{
					authBackendInfo{
						Type: "userpass",
					},
				},
				Users: []userAccount{
					userAccount{
						Name:     "test",
						Password: "secret",
						Policies: []string{
							"policy2",
						},
					},
				},
			}
			err = injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			user, err = vault.GetUser(userName)
			So(err, ShouldBeNil)
			So(user.Name, ShouldEqual, userName)
			So(len(user.Policies), ShouldEqual, 2)
			So(user.Policies, ShouldContain, "default")
			So(user.Policies, ShouldContain, "policy2")

			// TODO: validate that error is descriptively asking to mount Auth backend
		})
	})
}
