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
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestInjestSshOtpBackend(t *testing.T) {
	t.Skip("skipping test for now.")

	log.SetLevel(log.ErrorLevel)

	testEnvPath := "../testing/integration/ssh/docker-compose.yml"

	vault, key, deferFn, err := createTestProject(testEnvPath, "ssl/ca.crt", "ssl/vault_client.crt", "ssl/vault_client.key", nil, false)
	if deferFn != nil {
		defer deferFn()
	}
	if err != nil {
		t.Fatal("Failed to initialize Vault client")
	}
	if key == "" {
		t.Fatal("Got an Empty security key")
	}

	Convey("Configure OTP for SSH", t, func() {
		Convey("Role is created", func() {
			mountType := "ssh"
			mountPath := "ssh"
			mountDescr := "SSH backend"
			policies := vaultConfig{
				Mounts: []mountInfo{
					mountInfo{
						Path:        mountPath,
						Type:        mountType,
						Description: mountDescr,
					},
				},
				Roles: []rolePolicy{
					{
						Name: "otp_key_role",
						Path: mountPath,
						Properties: map[string]string{
							"key_type":     "otp",
							"default_user": "admin",
							"cidr_list":    "172.17.0.5/32",
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
			ssh := (*mounts)[mountPath]

			So(ssh, ShouldNotBeNil)
			So(ssh.Description, ShouldEqual, mountDescr)

			data := map[string]interface{}{
				//"key_type": "otp",
				//"default_user": "admin",
				//"cidr_list": "172.17.0.0/24,172.17.0.3/32",
				"ip": "172.17.0.5",
			}
			secret, err := vault.Client.Logical().Write("/ssh/creds/otp_key_role", data)
			if err != nil {
				t.Fatalf("Failed to issue a certificate. %#v", err)
			}
			log.Infof("Got secret: %#v", *secret)

			password := getStringFromMap(&secret.Data, "key", "")
			So(password, ShouldNotBeBlank)

			roles, err := vault.ListRoles(ssh)
			log.Debugf("Found %d roles", len(roles))
			for id, role := range roles {
				log.Debugf("Role: id %s, role: %s", id, role)
			}
			So(roles, ShouldContain, "otp_key_role")

			result, err := ssh_execute("192.168.99.100", "8222", "admin", password, "echo Hello")
			So(err, ShouldBeNil)
			So(strings.TrimSpace(result), ShouldEqual, "Hello")
		})
	})
}
