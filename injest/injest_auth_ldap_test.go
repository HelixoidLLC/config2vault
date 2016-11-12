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

func TestInjestAuthLdap(t *testing.T) {
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

	Convey("LDAP Auth backend", t, func() {
		Convey("config and group mapping", func() {

			policies := vaultConfig{
				AuthBackends: []authBackendInfo{
					authBackendInfo{
						Type:        "ldap",
						Description: "ldap",
						Config: []map[string]interface{}{
							map[string]interface{}{
								"properties": map[string]interface{}{
									"url": "ldaps://ldap.example.com",
									"userattr": "uid",
									"userdn": "ou=Users,dc=example,dc=com",
									"discoverdn": "true",
									"groupdn": "ou=Groups,dc=example,dc=com",
									"insecure_tls": "false",
									"starttls": "true",
								},
							},
							map[string]interface{}{
								"path": "groups/devops",
								"properties": map[string]interface{}{
									"policies": "otp-ssh",
								},
							},
						},
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)
		})
	})
}
