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
	"fmt"
)

func (vault *vaultClient) UpdateAuthBackends(authMounts *[]authBackendInfo) error {
	currentAuthMounts, err := vault.ListAuthBackends()
	if err != nil {
		return err
	}
	current_auth_mounts := make(map[string]interface{}, len(*currentAuthMounts))
	for path, _ := range *currentAuthMounts {
		log.Debugf("Found '%s' Auth backend", path)
		current_auth_mounts[path] = nil
	}
	ignoreBackends := map[string]bool{
		"token": true,
	}

	for authMountID, authBackend := range *authMounts {

		// Defaulting empty path to the Type of the mount
		if authBackend.Path == "" {
			authBackend.Path = authBackend.Type
			(*authMounts)[authMountID].Path = authBackend.Path
		}

		log.Debugf("Mounting '%s' auth backend", authBackend.Path)

		if _, ok := (*currentAuthMounts)[authBackend.Path]; ok {

			// TODO: optimise this
			// Reconverge config for the existing mounts
			if err := vault.ConfigureAuthBackend(&authBackend); err != nil {
				return err
			}

			// Similar mount is present in the system
			log.Infof("Skipping '%s' auth mount", authBackend.Type)
			delete(current_auth_mounts, authBackend.Path)

			// TODO: reapply configuration
			continue
		}

		log.Debug("Here  ####")

		if err := vault.EnableAuthBackend(&authBackend); err != nil {
			return err
		}

		if err := vault.ConfigureAuthBackend(&authBackend); err != nil {
			return err
		}
	}

	for path, _ := range current_auth_mounts {
		if ignoreBackends[path] {
			continue
		}
		log.Debugf("Disabling runaway auth mount: %s", path)
		if err := vault.DisableAuthBackend(path); err != nil {
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
		log.Errorf("Failed to mount a new Auth backend. %v", err)
		return errors.New("Failed to mount a new Auth backend")
	}

	return nil
}

func (vault *vaultClient) DisableAuthBackend(authBackendPath string) error {

	log.Infof("Removing auth backend at path '%s'.", authBackendPath)
	if err := vault.Client.Sys().DisableAuth(authBackendPath); err != nil {
		log.Errorf("Failed to disable Auth backend. %v", err)
		return errors.New("Failed to disable Auth backend")
	}

	return nil
}

func (vault *vaultClient) ConfigureAuthBackend(authBackend *authBackendInfo) error {
	log.Infof("Configuring '%s' auth backend", authBackend.Path)
	// TODO: read existing config, compare and apply only if not equal
	for _, props := range authBackend.Config {
		path, ok := props["path"]
		if !ok {
			path = "config"
		}
		properties := getStringMapInterfaceFromMap(&props, "properties", nil)
		if properties == nil {
			log.Fatalf("Configuration section '%s' present but no properties can be found", authBackend.Path)
			return errors.New("Can't have auth config section without properties")
		}

		configPath := fmt.Sprintf("auth/%s/%s", authBackend.Path, path)
		log.Debugf("Writing auth backend '%s' properties to path: %s", authBackend.Path, configPath)
		if _, err := vault.Client.Logical().Write(configPath, *properties); err != nil {
			log.Errorf("Failed to write properties to path '%s': %v", configPath, err)
			return errors.New("Failed to configure Auth Backend: " + authBackend.Path)
		}
	}
	return nil
}
