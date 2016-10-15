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

func (vault *vaultClient) ListPolicies() (*map[string]policyDefiniton, error) {
	policies, err := vault.Client.Sys().ListPolicies()
	if err != nil {
		log.Errorf("Failed to retreive existing policies: %v", err)
		return nil, errors.New("Failed to retreive existing policies")
	}

	existingPolicies := make(map[string]policyDefiniton)
	for _, policy := range policies {
		rules, err := vault.Client.Sys().GetPolicy(policy)
		if err != nil {
			log.Errorf("Failed to retreive existing policies: %v", err)
			return nil, errors.New("Failed to retreive existing policies")
		}
		txtRule := rules
		if txtRule == "" {
			txtRule = "(none)"
		}
		log.Debugf("Existing policy '%s' has rules: %s", policy, txtRule)

		existingPolicy := policyDefiniton{
			Name:  policy,
			Rules: rules,
		}

		existingPolicies[policy] = existingPolicy
	}

	return &existingPolicies, nil
}

func (vault *vaultClient) ReconcilePolicies(oldPolicies *map[string]policyDefiniton, newPolicies *[]policyDefiniton, removeDelta bool) error {
	if len(*newPolicies) == 0 {
		log.Info("No changes to the policies. Skipping ....")
		return nil
	}
	log.Debug("Reconciling policies ...")
	for _, newPolicy := range *newPolicies {
		if newPolicy.Rules == "${ignore}" {
			log.Info("Ignoring policy: " + newPolicy.Name)
			delete(*oldPolicies, newPolicy.Name)
			continue
		}
		oldPolicy, exist := (*oldPolicies)[newPolicy.Name]
		updatePolicy := false
		if !exist {
			log.Info("Applying new policy: " + newPolicy.Name)
			updatePolicy = true
		}
		if oldPolicy.Rules != newPolicy.Rules {
			log.Warning("Updating policy: " + newPolicy.Name)
			updatePolicy = true
		}

		if updatePolicy {
			err := vault.ApplyPolicy(&newPolicy)
			if err != nil {
				return err
			}
		} else {
			log.Info("Keeping unmodified policy: " + newPolicy.Name)
		}
		// No changes to the policy have been found - keeping it as-is
		delete(*oldPolicies, newPolicy.Name)
	}
	for _, oldPolicy := range *oldPolicies {
		log.Error("Found runaway policy: " + oldPolicy.Name)
		if removeDelta {
			knownDefaultPolicies := map[string]interface{} {
				"root": nil,
				"default": nil,
				"response-wrapping": nil,
			}
			if _, found := knownDefaultPolicies[oldPolicy.Name]; found {
				log.Warningf("Refusing to delete '%s' policy. Skipping ...", oldPolicy.Name)
				continue
			}
			log.Info("Deleting policy: " + oldPolicy.Name)
			if err := vault.Client.Sys().DeletePolicy(oldPolicy.Name); err != nil {
				log.Error("Failed to remove policy: " + oldPolicy.Name)
				return errors.New("Failed to remove policy: " + oldPolicy.Name)
			}
		}
	}
	return nil
}

func (vault *vaultClient) ApplyPolicy(policy *policyDefiniton) error {
	err := vault.Client.Sys().PutPolicy(policy.Name, policy.Rules)
	if err != nil {
		log.Error(err)
		return errors.New("Failed to apply policy")
	}
	return nil
}
