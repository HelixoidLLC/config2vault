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

func TestInjestMounts(t *testing.T) {
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

	Convey("A previous mount should be removed", t, func() {
		SkipConvey("A non-declared mount should be removed", func() {
			mountType := "ssh"
			expectedPath := "ssh_expected"
			unexpectedPath := "ssh_unexpected"
			policies := vaultConfig{
				Mounts: []mountInfo{
					{
						Type: mountType,
						Path: expectedPath,
					},
					{
						Type: mountType,
						Path: unexpectedPath,
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			currentAuthMounts, err := vault.ListMounts()
			So(err, ShouldBeNil)
			_, ok := (*currentAuthMounts)[expectedPath]
			So(ok, ShouldBeTrue)
			_, ok = (*currentAuthMounts)[unexpectedPath]
			So(ok, ShouldBeTrue)

			log.Debug("############# Test mount revocation")

			policiesNew := vaultConfig{
				Mounts: []mountInfo{
					{
						Type: mountType,
						Path: expectedPath,
					},
				},
			}
			log.Infof("%#v", policiesNew)
			err = injestConfig(vault, &policiesNew)
			So(err, ShouldBeNil)

			newAuthMounts, err := vault.ListMounts()
			So(err, ShouldBeNil)
			_, ok = (*newAuthMounts)[expectedPath]
			So(ok, ShouldBeTrue)
			_, ok = (*newAuthMounts)[unexpectedPath]
			So(ok, ShouldBeFalse)

		})
		Convey("A mount is ignored if marked as such", func() {

			mountType := "ssh"
			expectedPath := "ssh_expected"
			ignoredPath := "ssh_unexpected"
			policies := vaultConfig{
				Mounts: []mountInfo{
					{
						Type: mountType,
						Path: expectedPath,
					},
					{
						Type: mountType,
						Path: ignoredPath,
					},
				},
			}
			err := injestConfig(vault, &policies)
			So(err, ShouldBeNil)

			currentAuthMounts, err := vault.ListMounts()
			So(err, ShouldBeNil)
			_, ok := (*currentAuthMounts)[expectedPath]
			So(ok, ShouldBeTrue)
			_, ok = (*currentAuthMounts)[ignoredPath]
			So(ok, ShouldBeTrue)

			log.Debug("############# Test mount revocation")

			policiesNew := vaultConfig{
				Mounts: []mountInfo{
					{
						Type: mountType,
						Path: expectedPath,
					},
					{
						Type: "${ignore}",
						Path: ignoredPath,
					},
				},
			}
			log.Infof("%#v", policiesNew)
			err = injestConfig(vault, &policiesNew)
			So(err, ShouldBeNil)

			newAuthMounts, err := vault.ListMounts()
			So(err, ShouldBeNil)
			_, ok = (*newAuthMounts)[expectedPath]
			So(ok, ShouldBeTrue)
			_, ok = (*newAuthMounts)[ignoredPath]
			So(ok, ShouldBeTrue)

		})
		Convey("Mount is removed if not anymore on the list", nil)
	})
}
