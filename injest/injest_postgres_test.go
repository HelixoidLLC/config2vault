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
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	. "github.com/smartystreets/goconvey/convey"
)

func TestInjestPostgressBackend(t *testing.T) {
	t.Skip("skipping test for now.")

	log.SetLevel(log.ErrorLevel)

	checkDbAccessFunc := func(username, password string) bool {
		log.Debug("Waiting for DB to start ...")
		connectionParams := fmt.Sprintf("dbname=postgres user=%s password=%s host=192.168.99.100 sslmode=disable", username, password)
		log.Debug("Connection options: " + connectionParams)
		db, err := sql.Open("postgres", connectionParams)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()
		count := 10
		retryFn := func(err error) bool {
			log.Error(err)
			time.Sleep(500 * time.Millisecond)
			count--
			return count > 0
		}
		for ok := true; ok; {
			log.Debug("Trying ...")
			rows, err := db.Query("SELECT 1 FROM pg_database WHERE datname='postgres'")
			if err != nil {
				if retryFn(err) {
					continue
				} else {
					return false
				}
			}
			rows.Next()
			var count int
			err = rows.Scan(&count)
			if err != nil {
				if retryFn(err) {
					continue
				} else {
					return false
				}
			}
			log.Infof("Got result: %d", count)
			break
		}

		log.Debug("Postgres is up and available")
		return true
	}

	vault, key, deferFn, err := createTestProject("../testing/integration/postgres/docker-compose.yml", "", "", "", func() bool {
		return checkDbAccessFunc("postgres", "password")
	}, false)
	if deferFn != nil {
		defer deferFn()
	}
	if err != nil {
		t.Fatal("Failed to initialize Vault client")
	}
	if key == "" {
		t.Fatal("Got an Empty security key")
	}

	Convey("Postgres backend config injest", t, func() {
		Convey("Role is created", func() {
			mountType := "postgresql"
			mountPath := "myPostgres"
			mountDescr := "Postgres backend"

			policies := vaultConfig{
				Mounts: []mountInfo{
					mountInfo{
						Path:        mountPath,
						Type:        mountType,
						Description: mountDescr,
						Config: []map[string]interface{}{
							{
								"path": "connection",
								"properties": map[string]string{
									"connection_url": "postgresql://postgres:password@192.168.99.100:5432/postgres?sslmode=disable",
								},
							},
							{
								"path": "lease",
								"properties": map[string]string{
									"lease":     "1h",
									"lease_max": "24h",
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
							"sql": `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`,
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

			roles, err := vault.ListRoles(consulMount)
			log.Debugf("Found %d roles", len(roles))
			for id, role := range roles {
				log.Debugf("Role: id %s, role: %s", id, role)
			}
			So(len(roles), ShouldEqual, 1)

			secret, err := vault.Client.Logical().Read(mountPath + "/creds/readonly")
			if err != nil {
				t.Fatal("Failed to get secret. Err: %#v", err)
			}
			username := secret.Data["username"].(string)
			password := secret.Data["password"].(string)

			hasAccess := checkDbAccessFunc(username, password)
			So(hasAccess, ShouldBeTrue)
		})
	})
}
