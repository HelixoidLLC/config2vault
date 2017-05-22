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
	"path/filepath"
)

func (vault *vaultClient) UpdateTransitKeys(transitKeys *[]transitKey) error {
	log.Debug("Updating transit keys")

	if len(*transitKeys) == 0 {
		log.Info("No Transit Keys to injest")
	} else {
		for _, entry := range *transitKeys {

			err := vault.UpdateTransitKey(&entry)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (vault *vaultClient) UpdateTransitKey(key *transitKey) error {

	path := filepath.Join("transit/keys", key.Name)
	log.Debugf("Creating transit key '%s'", path)

	data := make(map[string]interface{})
	if key.Type != "" {
		data["type"] = key.Type  // defaults to: aes256-gcm96
	}

	if _, err := vault.Client.Logical().Write(path, data); err != nil {
		log.Fatalf("Failed to kreate key '%s'. %v", key.Name, err)
		return err
	}
	log.Infof("Created key '%s'", key.Name)

	return nil
}
