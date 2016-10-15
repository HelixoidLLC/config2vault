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
	"errors"
)

func (vault *vaultClient) UpdateAuthBackends(authMounts *[]authBackendInfo) error {
	currentAuthMounts, err := vault.ListAuthBackends()
	if err != nil {
		return err
	}
	for k, _ := range *currentAuthMounts {
		log.Debugf("Found '%s' Auth backend", k)
	}

	for authMountID, authBackend := range *authMounts {
		log.Debugf("Mounting %s auth backend", authBackend.Path)

		// Defaulting empty path to the Type of the mount
		if authBackend.Path == "" {
			authBackend.Path = authBackend.Type
			(*authMounts)[authMountID].Path = authBackend.Path
		}

		if _, ok := (*currentAuthMounts)[authBackend.Path]; ok {
			// Similar mount is present in the system
			log.Info("Skipping Auth mount: " + authBackend.Type)
			continue
		}

		err := vault.EnableAuthBackend(&authBackend)
		if err != nil {
			return err
		}
	}

	return nil
}

func (vault *vaultClient) ListAuthBackends() (*map[string]authBackendInfo, error) {
	authMounts, err := vault.Client.Sys().ListAuth()
	if err != nil {
		log.Fatalf("Can't get Vault mounts. %v", err)
	}

	vaultAuthMounts := map[string]authBackendInfo{}

	for authPath, authMount := range authMounts {
		log.Infof("Auth Mount %s: %s (%s)", authPath, authMount.Type, authMount.Description)

		oldMount := authBackendInfo{
			Path:        TrimSuffix(authPath, "/"),
			Type:        authMount.Type,
			Description: authMount.Description,
		}
		vaultAuthMounts[oldMount.Path] = oldMount
	}

	return &vaultAuthMounts, nil
}

func (vault *vaultClient) EnableAuthBackend(authBackend *authBackendInfo) error {

	log.Infof("Adding new auth backend of type '%s' at path '%s'.", authBackend.Type, authBackend.Path)
	// TODO: validate if there is a duplicate path in the sytem
	if err := vault.Client.Sys().EnableAuth(authBackend.Path, authBackend.Type, authBackend.Description); err != nil {
		log.Errorf("Failed to create a new Auth mount. %v", err)
		return errors.New("Failed to create a new mount")
	}

	return nil
}
