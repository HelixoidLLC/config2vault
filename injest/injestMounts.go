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

	vaultapi "github.com/hashicorp/vault/api"
)

func (vault *vaultClient) UpdateMounts(mounts *[]mountInfo) error {
	currentMounts, err := vault.ListMounts()
	if err != nil {
		log.Error("Failed to get list of mounts")
		return err
	}

	for mountID, newMount := range *mounts {
		// Defaulting empty path to the Type of the mount
		if newMount.Path == "" {
			(*mounts)[mountID].Path = newMount.Type
			newMount.Path = newMount.Type
			log.Debugf("Defaulting path for mount of type '%s' to '%s'", newMount.Type, newMount.Path)
		}

		// validate if there is a duplicate path in the system
		if _, ok := (*currentMounts)[newMount.Path]; ok {
			// Similar mount is present in the system
			log.Info("Skipping mount: " + newMount.Type)
			delete(*currentMounts, newMount.Path)
			continue
		}

		// TODO: update mount lease times if were changed since last creation
		vault.AddMount(&newMount)

		if err := vault.ApplyMountConfig(newMount); err != nil {
			log.Errorf("Failed to configure new mount. %v", err)
			log.Info("Unmounting ...")
			if err := vault.Client.Sys().Unmount(newMount.Path); err != nil {
				log.Errorf("Failed to unmount failed mount. %v", err)
				return errors.New("Failed to remove failed mount")
			}

			return errors.New("Failed to configure new mount.")
		}
		log.Debug("Mount has been added")
	}
	ignoreMounts := map[string]bool{
		"cubbyhole": true,
		"sys":       true,
		"secret":    true,
	}
	for path := range *currentMounts {
		if ignoreMounts[path] {
			continue
		}
		log.Warningf("Found unmanaged mount: %s. Removing ...", path)
		vault.UnMount(path)
	}

	return err
}

func (vault *vaultClient) ListMounts() (*map[string]mountInfo, error) {
	mounts, err := vault.Client.Sys().ListMounts()
	if err != nil {
		log.Fatalf("Can't get Vault mounts. %v", err)
	}

	vaultMounts := map[string]mountInfo{}

	for mountPath, mount := range mounts {
		log.Infof("Mount '%s', type: %s, descr: %s", mountPath, mount.Type, mount.Description)
		oldMount := mountInfo{
			Path:        TrimSuffix(mountPath, "/"),
			Type:        mount.Type,
			Description: mount.Description,
		}
		vaultMounts[oldMount.Path] = oldMount
	}
	log.Debugf("Found %d mounts", len(mounts))

	return &vaultMounts, nil
}

func (vault *vaultClient) AddMount(mount *mountInfo) error {
	newMountInfo := vaultapi.MountInput{
		Type:        mount.Type,
		Description: mount.Description,
		Config: vaultapi.MountConfigInput{
			DefaultLeaseTTL: mount.DefaultLeaseTTL,
			MaxLeaseTTL:     mount.MaxLeaseTTL,
		},
	}
	log.Infof("Adding new mount of type '%s' at path '%s'.", mount.Type, mount.Path)

	if err := vault.Client.Sys().Mount(mount.Path, &newMountInfo); err != nil {
		log.Errorf("Failed to create a new mount. %v", err)
		return errors.New("Failed to create a new mount")
	}
	return nil
}

func (vault *vaultClient) UnMount(path string) error {
	if err := vault.Client.Sys().Unmount(path); err != nil {
		log.Errorf("Failed to unmount %s. %v", path, err)
		return err
	}

	return nil
}
