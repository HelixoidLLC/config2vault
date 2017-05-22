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

	b64 "encoding/base64"
	. "github.com/smartystreets/goconvey/convey"
)

func TestInjestTransitKeys(t *testing.T) {
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

	Convey("Transit Backend", t, func() {
		Convey("Key is created", func() {
			mount := "transit"
			keyName := "test_key"
			testContent := "test"
			policies := vaultConfig{
				Mounts: []mountInfo{
					mountInfo{
						Path:        mount,
						Type:        mount,
						Description: mount,
					},
				},
				TransitKeys: []transitKey{
					transitKey{
						//Type: "aes256-gcm96",
						Name: keyName,
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			data := map[string]interface{}{
				"plaintext": b64.StdEncoding.EncodeToString([]byte(testContent)),
			}

			// Encrypt
			secret, err := vault.Client.Logical().Write("transit/encrypt/"+keyName, data)
			So(err, ShouldBeNil)

			result := getStringFromMap(&secret.Data, "ciphertext", "")
			So(result, ShouldNotBeEmpty)

			// Decrypt
			data = map[string]interface{}{
				"ciphertext": result,
			}
			secret, err = vault.Client.Logical().Write("transit/decrypt/"+keyName, data)
			So(err, ShouldBeNil)

			result = getStringFromMap(&secret.Data, "plaintext", "")
			So(result, ShouldNotBeEmpty)

			content, _ := b64.StdEncoding.DecodeString(result)
			So(string(content), ShouldEqual, testContent)
		})
	})
}
