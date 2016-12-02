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
	"config2vault/config"
	"config2vault/log"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	consulapi "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-cleanhttp"
	vaultapi "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type vaultClient struct {
	Token  string
	Client *vaultapi.Client
}

type mountInfo struct {
	Type               string                   `yaml:"type"`
	Description        string                   `yaml:"description,omitempty"`
	Path               string                   `yaml:"path,omitempty"`
	DefaultLeaseTTL    string                   `yaml:"default_lease_ttl,omitempty"`
	MaxLeaseTTL        string                   `yaml:"max_lease_ttl,omitempty"`
	PolicyBase64Encode bool                     `yaml:"policy_base64_encode,omitempty"`
	Config             []map[string]interface{} `yaml:"config,omitempty"`
}

type propertyBag map[string]interface{}
type propertyBagArray []propertyBag

type authBackendInfo struct {
	Type        string                   `yaml:"type"`
	Description string                   `yaml:"description,omitempty"`
	Path        string                   `yaml:"path"`
	Config      []map[string]interface{} `yaml:"config,omitempty"`
}

type rolePolicy struct {
	Name       string            `yaml:"name"`
	Path       string            `yaml:"path"`
	Properties map[string]string `yaml:"properties"`
}

type userAccount struct {
	Name     string   `yaml:"name"`
	Password string   `yaml:"password,omitempty"`
	Policies []string `yaml:"policies,omitempty"`
	Ttl      string   `yaml:"ttl,omitempty"`
	MaxTtl   string   `yaml:"max_ttl,omitempty"`
}

type policyDefiniton struct {
	Name  string `yaml:"name"`
	Rules string `yaml:"rules,omitempty"`
}

type appRoleProperties struct {
	Role            string   `yaml:"role"`
	Policies        []string `yaml:"policies,omitempty"`
	SecretIdTtl     string   `yaml:"secret_id_ttl,omitempty"`
	TokenTtl        string   `yaml:"token_ttl,omitempty"`
	TokenMaxTtl     string   `yaml:"token_max_ttl,omitempty"`
	SecretIdNumUses int      `yaml:"secret_id_num_uses,omitempty"`
	BindSecretId    bool     `yaml:"bind_secret_id,omitempty"`
	Period          string   `yaml:"period,omitempty"`
	BoundCidrList   string   `yaml:"bound_cidr_list,omitempty"`
}

type fieldPair struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type genericSecret struct {
	Path   string      `yaml:"path"`
	Fields []fieldPair `yaml:"fields"`
}

type transitKey struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
	// derived
	// convergent_encryption
}

type vaultConfig struct {
	Mounts       []mountInfo         `yaml:"mounts,omitempty"`
	AuthBackends []authBackendInfo   `yaml:"auth,omitempty"`
	Roles        []rolePolicy        `yaml:"roles,omitempty"`
	Users        []userAccount       `yaml:"users,omitempty"`
	Policies     []policyDefiniton   `yaml:"policies,omitempty"`
	AppRoles     []appRoleProperties `yaml:"approles,omitempty"`
	Secrets      []genericSecret     `yaml:"secrets,omitempty"`
	TransitKeys  []transitKey        `yaml:"transit_keys,omitempty"`
}

func InjestConfig(config *vaultConfig) error {
	vault, err := Reconnect()
	if err != nil {
		return errors.New("Can't create Vault client")
	}

	return injestConfig(vault, config)
}

func ImportPath(path string) *vaultConfig {

	masterConfig := vaultConfig{}

	filename, _ := filepath.Abs(path)
	fileInfo, _ := os.Stat(filename)
	if fileInfo.IsDir() {
		files, _ := ioutil.ReadDir(filename)
		for _, file := range files {
			if file.IsDir() {
				continue
			}

			switch filepath.Ext(file.Name()) {
			case ".yml":
				break
			case ".yaml":
				break
			default:
				log.Debug("Skipping file ...")
				continue
			}

			ImportFile(filepath.Join(filename, file.Name()), &masterConfig)
		}
	} else {
		ImportFile(path, &masterConfig)
	}

	return &masterConfig
}

func ImportFile(filePath string, masterConfig *vaultConfig) error {
	log.Info("Loading file: " + filePath)

	conf, err := ReadConfigFile(filePath)
	if err != nil {
		log.Fatal("Failed to read config file.")
		return errors.New("Failed to read config file.")
	}

	masterConfig.mergeConfig(conf)
	return nil
}

func (masterConfig *vaultConfig) mergeConfig(newConfig *vaultConfig) {
	(*masterConfig).Mounts = append(masterConfig.Mounts, newConfig.Mounts...)
	(*masterConfig).AuthBackends = append(masterConfig.AuthBackends, newConfig.AuthBackends...)
	(*masterConfig).Roles = append(masterConfig.Roles, newConfig.Roles...)
	(*masterConfig).Users = append(masterConfig.Users, newConfig.Users...)
	(*masterConfig).Policies = append(masterConfig.Policies, newConfig.Policies...)
	(*masterConfig).AppRoles = append(masterConfig.AppRoles, newConfig.AppRoles...)
	(*masterConfig).Secrets = append(masterConfig.Secrets, newConfig.Secrets...)
}

func injestConfig(vault *vaultClient, conf *vaultConfig) error {
	// ###   Auth
	if vault.UpdateAuthBackends(&conf.AuthBackends) != nil {
		return errors.New("Failed to update Auth mounts")
	}

	// ###   Mounts
	if vault.UpdateMounts(&conf.Mounts) != nil {
		return errors.New("Failed to update mounts")
	}
	mountMap := map[string]mountInfo{}
	for _, mi := range conf.Mounts {
		mountMap[mi.Path] = mi
	}

	// ###   Policies
	existingPolicies, err := vault.ListPolicies()
	if err != nil {
		return errors.New("Failed to get list of existing policies")
	}

	if vault.ReconcilePolicies(existingPolicies, &conf.Policies, true) != nil {
		return errors.New("Failed to reconcile new and existing policies")
	}

	// ###   Roles
	log.Debug("Applying roles")
	existingRoles := map[string][]string{}
	// TODO: remove "runaway" mounts
	for _, mount := range conf.Mounts {
		roles, _ := vault.ListRoles(mount)
		log.Infof("Detected existing roles at '%s': %v", mount.Path, roles)
		existingRoles[mount.Path] = roles
	}

	if vault.ApplyRoles(mountMap, conf.Roles, &existingRoles) != nil {
		return errors.New("Failed to apply roles")
	}

	for mount, roles := range existingRoles {
		if len(roles) > 0 {
			log.Warningf("For mount '%s' found runaway roles %v. Deleting ...", mount, roles)
			if err := vault.DeleteRoles(mount, roles); err != nil {
				log.Error("Failed to delete runaway roles from mount " + mount)
				return err
			}
		}
	}

	// ###   Users
	if vault.CreateUserAccounts(conf.Users) != nil {
		return errors.New("Failed to create User Accounts")
	}

	// ### AppRoles
	if vault.UpdateAppRoles(&conf.AppRoles) != nil {
		return errors.New("Failed to update Auth map")
	}

	// ### Generic Secrets
	if vault.UpdateGenericSecrets(&conf.Secrets) != nil {
		return errors.New("Failed to update Generic Secrets")
	}

	// ### Transit Keys
	if vault.UpdateTransitKeys(&conf.TransitKeys) != nil {
		return errors.New("Failed to update Transit Keys")
	}

	return nil
}

func ReadConfigFile(filePath string) (*vaultConfig, error) {
	config := vaultConfig{}

	filename, _ := filepath.Abs(filePath)
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatal(err)
	}

	return &config, nil
}

func GetConentEvenIfFile(policy string) (string, error) {
	if policy == "" {
		return "", nil
	}
	if policy[0] != '@' {
		return policy, nil
	}

	// If the property content starts from a character @ - treat it as a file name and read the content from the file
	policyPath := string(policy[1:len(policy)])
	filename, _ := filepath.Abs(policyPath)
	log.Infof("Loading content from file %s", filename)

	policyBody, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Error(err)
		return "", errors.New("Failed to load policy file")
	}

	return string(policyBody), nil
}

func GetStringMap(in map[interface{}]interface{}) map[string]string {
	log.Debug("GetStringMap")
	out := make(map[string]string)
	for key, value := range in {
		switch key := key.(type) {
		case string:
			switch value := value.(type) {
			case string:
				out[key] = value
			}
		}
	}
	return out
}

func (vault *vaultClient) ApplyMountConfig(mount mountInfo) error {

	log.Debug("Applying Mount configuration")
	for _, cfg := range mount.Config {
		path, ok := cfg["path"]
		if !ok {
			log.Error("Can't find 'path' property for config: " + mount.Path)
			continue
		}
		config_path := filepath.Join(mount.Path, "config", path.(string))
		log.Info("Configuring path: " + config_path)

		data := make(map[string]interface{})

		if ca_bundle_i, ok := cfg["ca_bundle"]; ok {
			if ca_bundle_i == nil {
				log.Error("Empty ca_bundle. Skipping ...")
				continue
			}
			ca_bundle, success := ca_bundle_i.(map[string]string)
			if !success {
				ca_bundle_ii, success := ca_bundle_i.(map[interface{}]interface{})
				if !success {
					log.Error("Can't parse ca_bundle. Skipping ...")
					continue
				}
				ca_bundle = GetStringMap(ca_bundle_ii)
			}
			key, _ := GetConentEvenIfFile(ca_bundle["key"])
			key = strings.TrimRight(key, "\n")
			cert, _ := GetConentEvenIfFile(ca_bundle["cert"])
			cert = strings.TrimRight(cert, "\n")
			data["pem_bundle"] = cert + "\n" + key
		} else if properties, ok := cfg["properties"]; ok {
			for key, value := range properties.(map[string]string) {
				data[key] = value
			}
		}

		log.Debugf("Configuring mount with data: %#v", data)
		_, err := vault.Client.Logical().Write(config_path, data)
		if err != nil {
			errStr := fmt.Sprintf("Failed to configure mount. %v", err)
			log.Error(errStr)
			return errors.New(errStr)
		}
		log.Debug("Wrote configuration to path %s: %#v", config_path, data)
	}

	return nil
}

func Reconnect() (*vaultClient, error) {
	vault := vaultClient{}

	address := config.Conf.Url
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		log.Fatal("Can't find address of a Vault server")
		return nil, errors.New("Can't find address of a Vault server")
	}

	token := config.Conf.Token
	if token == "" {
		vault.Token = os.Getenv("VAULT_TOKEN")
	}

	// TODO: check all the ENV vars
	// VAULT_CACERT
	// VAULT_CAPATH
	// VAULT_CLIENT_CERT
	// VAULT_CLIENT_KEY
	// VAULT_SKIP_VERIFY

	ca_file_path, err := filepath.Abs(config.Conf.CaFile)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Can't locate CA file")
	}
	vault_cert_path, err := filepath.Abs(config.Conf.CertFile)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Can't locate Vault Cert file")
	}
	vault_key_path, err := filepath.Abs(config.Conf.KeyFile)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("Can't locate Vault Key file")
	}

	_vaultClient, err := createClient(address, ca_file_path, vault_cert_path, vault_key_path)
	if err == nil {
		vault.Client = _vaultClient
	} else {
		log.Fatal("Failed to create the vault client")
		return nil, errors.New("Failed to create the vault client")
	}

	if token != "" {
		vault.Token = token
		vault.Client.SetToken(token)
	} else {
		log.Fatal("Can't locate token for Vault authentication")
		return nil, errors.New("Can't locate token for Vault authentication")
	}

	return &vault, nil
}

func createClient(address string, CaFile string, CertFile string, KeyFile string) (*vaultapi.Client, error) {
	config := vaultapi.DefaultConfig()
	config.Address = address

	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		config.HttpClient.Transport = createTlsTransport(CaFile, CertFile, KeyFile)
	} else {
		log.Debug("Created non-TLS client")
	}

	client, err := vaultapi.NewClient(config)

	return client, err
}

func createTlsTransport(CaFile string, CertFile string, KeyFile string) http.RoundTripper {

	tlsClientConfig, err := consulapi.SetupTLSConfig(&consulapi.TLSConfig{
		InsecureSkipVerify: true,
		CAFile:             CaFile,
		CertFile:           CertFile,
		KeyFile:            KeyFile,
	})

	// We don't expect this to fail given that we aren't
	// parsing any of the input, but we panic just in case
	// since this doesn't have an error return.
	if err != nil {
		panic(err)
	}

	transport := cleanhttp.DefaultPooledTransport()
	transport.TLSClientConfig = tlsClientConfig
	transport.TLSClientConfig.InsecureSkipVerify = true
	return transport
}

func TrimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}
