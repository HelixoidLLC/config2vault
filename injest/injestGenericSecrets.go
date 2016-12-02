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

func (vault *vaultClient) UpdateGenericSecrets(secrets *[]genericSecret) error {
	log.Debug("Updating secrets")
	currentSecrets, err := vault.ListSecrets()
	if err != nil {
		return err
	}

	if len(*secrets) == 0 {
		log.Info("No Secets to injest")
	} else {
		for _, entry := range *secrets {
			// Try to remove key path if present
			entry.Path = filepath.Join("secret", entry.Path)
			delete(*currentSecrets, entry.Path)
			err := vault.SetSecret(&entry)
			if err != nil {
				return err
			}
		}
	}

	for path, _ := range *currentSecrets {
		log.Warning("Leftover secret: " + path)
		vault.DeleteSecret(path)
	}

	return nil
}

func (vault *vaultClient) SetSecret(secret *genericSecret) error {
	data := make(map[string]interface{})
	for _, kpair := range secret.Fields {
		data[kpair.Key] = kpair.Value
	}
	_, err := vault.Client.Logical().Write(secret.Path, data)
	if err != nil {
		log.Fatalf("Failed to set secret '%s'. %#v", secret.Path, err)
		return err
	}
	log.Infof("Created secret '%s'", secret.Path)

	return nil
}

func (vault *vaultClient) ListSecrets() (secretsList *map[string]interface{}, err error) {
	m := make(map[string]interface{})
	secretsList = &m
	err = vault.listSecrets("secret", secretsList)
	log.Debugf("Found list of secrets: %v", *secretsList)
	return secretsList, err
}

func (vault *vaultClient) listSecrets(path string, result *map[string]interface{}) error {
	log.Debug("Listing secrets path: " + path)
	list, err := vault.Client.Logical().List(path)
	if err != nil {
		log.Errorf("Failed to list secrets. %v", err)
		return err
	}
	if list == nil {
		log.Debug("No secrets at this path")
		return nil
	}
	keys := getStringArrayFromMap(&list.Data, "keys", []string{})
	for _, k := range keys {
		fullSecretPath := path + k
		log.Debug("Secret path: " + fullSecretPath)
		if k[len(k)-1] == '/' {
			vault.listSecrets(fullSecretPath, result)
		} else {
			(*result)[fullSecretPath] = nil
		}
	}
	return nil
}

func (vault *vaultClient) DeleteSecret(path string) error {
	log.Debug("Deleting secret at path: " + path)
	_, err := vault.Client.Logical().Delete(path)
	return err
}
