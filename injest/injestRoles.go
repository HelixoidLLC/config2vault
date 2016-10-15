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
	"encoding/base64"
	"errors"
	"path/filepath"
)

func (vault *vaultClient) ApplyRoles(mounts map[string]mountInfo, rolePolicies []rolePolicy, existingRoles *map[string][]string) error {
	if len(rolePolicies) == 0 {
		log.Info("No Roles to apply.")
		return nil
	}
	for _, rolePol := range rolePolicies {
		newEntry := make(map[string]interface{})

		rolePath := filepath.Join(rolePol.Path, "roles", rolePol.Name)

		log.Info("Preparing policy for role path: " + rolePath)

		for propertyName, policy := range rolePol.Properties {
			newEntry[propertyName] = policy

			newEntry[propertyName], _ = GetConentEvenIfFile(policy)

			// If needed, encode for Consul
			if mounts[rolePol.Path].PolicyBase64Encode == true {
				encoded := make([]byte, base64.StdEncoding.EncodedLen(len(policy)))
				base64.StdEncoding.Encode(encoded, []byte(policy))

				newEntry[propertyName] = encoded
			}
		}

		log.Info("Applying policy to role path: " + rolePath)
		secret, err := vault.Client.Logical().Write(rolePath, newEntry)
		if err != nil {
			log.Error(err)
			return errors.New("Failed to apply policy to role path: " + rolePath)
		}
		if secret != nil {
			log.Debugf("Received secret: %#v", *secret)
		}

		if pathRoles, ok := (*existingRoles)[rolePol.Path]; ok {
			for i, roleName := range pathRoles {
				if roleName == rolePol.Name {
					// Delete item/element from slice
					pathRoles = append(pathRoles[:i], pathRoles[i+1:]...)
					break
				}
			}
			(*existingRoles)[rolePol.Path] = pathRoles
		}
	}

	return nil
}

func (vault *vaultClient) ListRoles(mount mountInfo) (roles []string, err error) {
	roles_path := filepath.Join(mount.Path, "roles")
	log.Debug("Dumping roles at path " + roles_path)
	secret, err := vault.Client.Logical().List(roles_path)
	if err != nil {
		// Note: Some secret backends do not implement such functionality
		log.Info("Can't get list of roles at path: " + roles_path)
		return roles, errors.New("Didn't get list of roles")
	}

	if secret != nil {
		keys := secret.Data["keys"]
		if keys != nil {
			rolesData := keys.([]interface{})
			for _, key := range rolesData {
				roles = append(roles, key.(string))
			}
		}
	}
	return roles, nil
}

func (vault *vaultClient) DeleteRoles(mountPath string, roles []string) error {
	for _, role := range roles {
		rolePath := filepath.Join(mountPath, "roles", role)

		_, err := vault.Client.Logical().Delete(rolePath)
		if err != nil {
			log.Error("Failed to delete role " + rolePath)
			return errors.New("Failed to delete role " + rolePath)
		}
		log.Info("Deleted " + rolePath)
	}
	return nil
}
