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

func TestInjestAuthAppidBackend(t *testing.T) {
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

	Convey("Enable AppID Auth backend", t, func() {
		Convey("Remove all approles if section is present and empty", nil)
		Convey("Role is created", func() {
			mountType := "approle"
			mountPath := "approle"
			mountDescr := "AppRole backend"
			roleName := "f808243f-27e0-4c78-9e3a-faccf0857373"
			policies := vaultConfig{
				AuthBackends: []authBackendInfo{
					authBackendInfo{
						Path:        mountPath,
						Type:        mountType,
						Description: mountDescr,
					},
				},
				AppRoles: []appRoleProperties{
					appRoleProperties{
						Policies: []string{
							"test_policy",
						},
						Role:            roleName,
						SecretIdTtl:     "10m",
						TokenTtl:        "20m",
						TokenMaxTtl:     "30m",
						SecretIdNumUses: 40,
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			currentAuthMounts, err := vault.ListAuthBackends()
			if err != nil {
				t.Fatal("Failed to get mounts")
			}
			pkiMount := (*currentAuthMounts)[mountPath]

			So(pkiMount, ShouldNotBeNil)
			So(pkiMount.Description, ShouldEqual, mountDescr)

			roleID, err := vault.GetAppRoleID(roleName)
			secretID, err := vault.GetAppRoleSecretID(roleName)

			So(err, ShouldBeNil)
			So(secretID, ShouldNotBeEmpty)
			log.Debugf("Got SecretID " + secretID)

			auth, err := vault.LoginAppRole(roleID, secretID)
			So(auth.ClientToken, ShouldNotBeNil)
		})
		Convey("Role is updated", func() {
			mountType := "approle"
			mountPath := "approle"
			mountDescr := "AppRole backend"
			roleID := "testrole1"
			policies := vaultConfig{
				AuthBackends: []authBackendInfo{
					authBackendInfo{
						Path:        mountPath,
						Type:        mountType,
						Description: mountDescr,
					},
				},
				AppRoles: []appRoleProperties{
					appRoleProperties{
						Role:            roleID,
						SecretIdTtl:     "10m",
						TokenTtl:        "20m",
						TokenMaxTtl:     "30m",
						SecretIdNumUses: 40,
						Policies: []string{
							"test_policy",
						},
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeEmpty)

			appRole, err := vault.GetAppRole(roleID)
			So(err, ShouldBeEmpty)
			So(appRole.SecretIdTtl, ShouldEqual, "600")

			log.Info("################### Update time")

			policies = vaultConfig{
				AuthBackends: []authBackendInfo{
					authBackendInfo{
						Path:        mountPath,
						Type:        mountType,
						Description: mountDescr,
					},
				},
				AppRoles: []appRoleProperties{
					appRoleProperties{
						Role:            roleID,
						SecretIdTtl:     "20m", // This is the change
						TokenTtl:        "20m",
						TokenMaxTtl:     "30m",
						SecretIdNumUses: 40, Policies: []string{
							"test_policy",
							"another_policy",
						},
					},
				},
			}
			err = injestConfig(vault, &policies)
			So(err, ShouldBeEmpty)

			appRole, err = vault.GetAppRole(roleID)
			So(err, ShouldBeEmpty)
			So(appRole.SecretIdTtl, ShouldEqual, "1200")
		})
	})
}
