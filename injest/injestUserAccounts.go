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
	"path"
	"strings"
	//"io"
	//"bytes"
)

func (vault *vaultClient) CreateUserAccounts(users []userAccount) error {
	if len(users) == 0 {
		return nil
	}

	log.Info("Creating User Accounts ...")
	for _, user := range users {

		data := make(map[string]interface{})
		if user.Policies != nil {
			data["policies"] = strings.Join(user.Policies, ",")
		}
		if user.Password != "" {
			data["password"] = user.Password
		}

		path := path.Join("auth/userpass/users", user.Name)
		log.Info("Creating/Updating user: " + path)
		_, err := vault.Client.Logical().Write(path, data)
		if err != nil {
			log.Errorf("Failed to create user '%s': %v", path, err)
			return errors.New("Failed to create user: " + path)
		}
	}
	return nil
}

func (vault *vaultClient) isUserPresent(currentAccounts *map[string]*map[string]*userAccount, newUser *userAccount) (*userAccount, error) {

	// TODO: make this more generic
	authPath := "userpass"
	authPathAccounts, found := (*currentAccounts)[authPath]
	if !found {
		var err error
		accountIDs, err := vault.ListUsers(authPath)
		found := false
		for _, id := range *accountIDs {
			if id == newUser.Name {
				found = true
				break
			}
		}
		if found {
			log.Debug("Found existing user with the same name: " + newUser.Name)
			_, err = vault.GetUser(newUser.Name)

			if err != nil {
				return nil, err
			}
		}
	}

	if authPathAccounts != nil {
		return (*authPathAccounts)[newUser.Name], nil
	}
	return nil, nil
}

func (vault *vaultClient) ListUsers(authPath string) (*[]string, error) {
	secret, err := vault.Client.Logical().List("auth/userpass/users")
	if err != nil {
		log.Error(err)
	}
	if secret == nil {
		return &[]string{}, nil
	}

	accountIDs := getStringArrayFromMap(&secret.Data, "keys", []string{})
	return &accountIDs, nil
}

func (vault *vaultClient) GetUser(userID string) (*userAccount, error) {
	secret, err := vault.Client.Logical().Read("auth/userpass/users/" + userID)
	if err != nil {
		log.Error(err)
	}
	if secret == nil {
		return nil, nil
	}

	user := userAccount{
		Name:     userID,
		Policies: strings.Split(getStringFromMap(&secret.Data, "policies", ""), ","),
		Ttl:      getStringFromMap(&secret.Data, "ttl", ""),
		MaxTtl:   getStringFromMap(&secret.Data, "max_ttl", ""),
	}

	return &user, nil
}
