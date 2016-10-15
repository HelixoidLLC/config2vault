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

	vaultapi "github.com/hashicorp/vault/api"
)

func (vault *vaultClient) UpdateAppRoles(newAppRoles *[]appRoleProperties) error {
	log.Debug("Applying AppRoles")
	if len(*newAppRoles) == 0 {
		log.Info("No AppRoles to apply")
		return nil
	}

	// TODO: this List fails if the backend is not mounted
	currentRoles, err := vault.ListAppRoles()
	if err != nil {
		return err
	}

	for _, newAppRole := range *newAppRoles {
		needRoleUpdate := true // Will create the role if not found
		if currentAppRole, ok, err := vault.getCachedAppRole(newAppRole.Role, currentRoles); ok || err != nil {
			if err != nil {
				// Error retreiving AppRole
				return err
			}
			// Found app role and will update only if they are not equal
			if currentAppRole.isEqual(&newAppRole) {
				log.Debug("Roles identical. Skipping ...")
				needRoleUpdate = false
			} else {
				log.Warningf("Roles '%s' are NOT identical. Updating ...", currentAppRole.Role)
				needRoleUpdate = true
			}
		}
		if needRoleUpdate {
			err := vault.SetAppRole(&newAppRole)
			if err != nil {
				// Failed to update app role
				return err
			}
		}
	}

	return nil
}

func (roleA *appRoleProperties) isEqual(roleB *appRoleProperties) bool {
	if roleA.SecretIdTtl != roleB.SecretIdTtl {
		return false
	}
	if roleA.TokenTtl != roleB.TokenTtl {
		return false
	}
	if roleA.TokenMaxTtl != roleB.TokenMaxTtl {
		return false
	}
	if roleA.SecretIdNumUses != roleB.SecretIdNumUses {
		return false
	}
	if roleA.BindSecretId != roleB.BindSecretId {
		return false
	}
	if roleA.Period != roleB.Period {
		return false
	}
	if roleA.BoundCidrList != roleB.BoundCidrList {
		return false
	}

	return areEqual(roleA.Policies, roleB.Policies, []string{"default"})
}

func areEqual(left []string, right []string, ignore []string) bool {
	leftSet := make(map[string]struct{})
	for _, s := range left {
		leftSet[s] = struct{}{}
	}
	ignoreSet := make(map[string]struct{})
	for _, s := range ignore {
		ignoreSet[s] = struct{}{}
	}
	for _, s := range right {
		if _, ok := leftSet[s]; ok {
			delete(leftSet, s)
		} else {
			if _, ok = ignoreSet[s]; !ok {
				return false
			}
		}
	}
	for s, _ := range leftSet {
		if _, ok := ignoreSet[s]; !ok {
			return false
		}
	}
	return true
}

func (vault *vaultClient) ListAppRoles() (roles map[string]*appRoleProperties, err error) {
	roles = make(map[string]*appRoleProperties)
	result, err := vault.Client.Logical().List("/auth/approle/role")
	if err != nil {
		log.Fatalf("Failed to list app roles. %#v", err)
		return roles, err
	}
	if result == nil {
		log.Debugf("No roles found.")
		return roles, nil
	}

	roleKeys := result.Data["keys"].([]interface{})
	log.Infof("Found %d App roles", len(roleKeys))

	for _, role := range roleKeys {
		roles[role.(string)] = nil
	}

	return roles, nil
}

func (vault *vaultClient) getCachedAppRole(roleKey string, roles map[string]*appRoleProperties) (*appRoleProperties, bool, error) {
	appRole := roles[roleKey]
	if appRole != nil {
		return appRole, true, nil
	}

	roleData, err := vault.GetAppRole(roleKey)
	if err != nil || roleData == nil {
		return nil, false, err
	}

	roles[roleKey] = roleData

	return roleData, true, nil
}

func (vault *vaultClient) SetAppRole(appRole *appRoleProperties) error {
	data := map[string]interface{}{
		"secret_id_ttl":      appRole.SecretIdTtl,
		"token_ttl":          appRole.TokenTtl,
		"token_max_ttl":      appRole.TokenMaxTtl,
		"secret_id_num_uses": appRole.SecretIdNumUses,
		"policies":           strings.Join(appRole.Policies, ","),
	}
	_, err := vault.Client.Logical().Write("/auth/approle/role/"+appRole.Role, data)
	if err != nil {
		log.Fatalf("Failed to create app role '%s'. %#v", appRole.Role, err)
		return err
	}
	info, err := vault.Client.Logical().Read("/auth/approle/role/" + appRole.Role + "/role-id")
	roleID := ""
	if info != nil && info.Data != nil {
		roleID = getStringFromMap(&info.Data, "role_id", "")
	}
	log.Infof("Created/Updated app role '%s' with RoleID: %s", appRole.Role, roleID)

	return nil
}

func (vault *vaultClient) GetAppRole(roleKey string) (*appRoleProperties, error) {
	log.Debugf("Retreiving policy for role '%s'", roleKey)
	role, err := vault.Client.Logical().Read("/auth/approle/role/" + roleKey)
	if err != nil {
		log.Fatalf("Failed to ready App Role '%s'", roleKey)
		return nil, err
	}
	log.Debugf("Role: %#v", role)
	if role == nil {
		return nil, nil
	}

	roleData := appRoleProperties{
		SecretIdNumUses: getIntFromMap(&role.Data, "secret_id_num_uses", -1),
		SecretIdTtl:     getStringFromMap(&role.Data, "secret_id_ttl", "-1"),
		TokenMaxTtl:     getStringFromMap(&role.Data, "token_max_ttl", "-1"),
		TokenTtl:        getStringFromMap(&role.Data, "token_ttl", "-1"),
		BindSecretId:    getBoolFromMap(&role.Data, "bind_secret_id", true),
		Period:          getStringFromMap(&role.Data, "period", "-1"),
		BoundCidrList:   getStringFromMap(&role.Data, "bound_cidr_list", ""),
		Policies:        getStringArrayFromMap(&role.Data, "policies", []string{}),
	}

	return &roleData, nil
}

func (vault *vaultClient) GetAppRoleID(roleKey string) (string, error) {

	info, err := vault.Client.Logical().Read("/auth/approle/role/" + roleKey + "/role-id")
	if err != nil {
		log.Error("Failed to get RoleID for Role: " + roleKey)
		return "", err
	}

	roleID := ""
	if info != nil && info.Data != nil {
		roleID = getStringFromMap(&info.Data, "role_id", "")
	}

	return roleID, nil
}

func (vault *vaultClient) GetAppRoleSecretID(roleKey string) (string, error) {
	secret, err := vault.Client.Logical().Write("/auth/approle/role/"+roleKey+"/secret-id", map[string]interface{}{})
	if err != nil {
		log.Error("Failed to get SecretID for Role: " + roleKey)
		return "", err
	}
	secretID := getStringFromMap(&secret.Data, "secret_id", "")
	return secretID, nil
}

func (vault *vaultClient) LoginAppRole(roleID string, secretID string) (*vaultapi.SecretAuth, error) {
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	secret, err := vault.Client.Logical().Write("/auth/approle/login", data)
	if err != nil {
		log.Error("Failed to Login with RoleID: " + roleID)
		return nil, err
	}
	log.Infof("Login info: %#v", secret.Auth)
	return secret.Auth, nil
}
