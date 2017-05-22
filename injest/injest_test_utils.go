// +build integration
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
	"bytes"
	"config2vault/docker_compose"
	"config2vault/log"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

func getHttpResponse(url string) (resp *http.Response, dfrFunc func(), err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err = client.Get(url)
	dfrFunc = func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}
	return resp, dfrFunc, err
}

func checkIfHttpAvailable(url string) bool {
	resp, dfrFunc, err := getHttpResponse(url)
	if dfrFunc != nil {
		defer dfrFunc()
	}
	if err != nil {
		return false
	}

	if resp.StatusCode != 200 {
		return false
	}
	var bodyBuf bytes.Buffer
	if _, err := io.Copy(&bodyBuf, resp.Body); err != nil {
		log.Debugf("ERROR: %v", err)
		return false
	}
	return true
}

func createTestProject(projectPath string, CaFile string, CertFile string, KeyFile string, checkProjectStatusFunc func() bool, useConsul bool) (*vaultClient, string, func(), error) {
	projectName := "testproject"

	project, err := docker_compose.NewDockerComposeProjectFromFile(projectName, projectPath)
	if err != nil {
		return nil, "", nil, err
	}
	connection, deferFn, err := project.Up()
	if err != nil {
		log.Fatalf("Failed to start docker project: %s", err)
		return nil, "", deferFn, err
	}
	log.Debugf("Connection: %s", connection)

	// check if Consul container up
	if useConsul {
		if running, _ := docker_compose.IsRunning(projectName, "consul"); !running {
			log.Fatalf("Consul Container is not running. Aborting ...")
			return nil, "", deferFn, errors.New("Container is not running. Aborting ...")
		}

		// TODO: define an exit timeout
		// TODO: externalize ports and scheme
		for ok := false; !ok; ok = checkIfHttpAvailable("https://" + connection + ":8501/v1/status/leader") {
			time.Sleep(500 * time.Millisecond)
		}
		time.Sleep(2 * time.Second)
		// TODO: this check for vault. Take it out of this block
		for ok := false; !ok; ok = checkIfHttpAvailable("https://" + connection + ":8200/v1/sys/init") {
			time.Sleep(500 * time.Millisecond)
		}
	}

	if checkProjectStatusFunc != nil {
		if !checkProjectStatusFunc() {
			return nil, "", deferFn, errors.New("Failed dependency check...")
		}
	}

	vault := vaultClient{}

	scheme := "http"
	if CaFile != "" {
		scheme = "https"
	}
	address := fmt.Sprintf("%s://%s:%s", scheme, connection, "8200")
	dir := filepath.Dir(projectPath)
	_vaultClient, err := createClient(address, filepath.Join(dir, CaFile), filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile))
	vault.Client = _vaultClient
	time.Sleep(500 * time.Millisecond)

	req := vaultapi.InitRequest{
		SecretShares:    1,
		SecretThreshold: 1,
	}
	resp, err := vault.Client.Sys().Init(&req)
	log.Debugf("Vault Init Resp: %v, %v", resp, err)

	if err != nil {
		return nil, "", nil, err
	}
	token := resp.RootToken
	log.Debug("Got token: " + token)

	r, err := vault.Client.Sys().Unseal(resp.Keys[0])
	if err != nil {
		return nil, "", deferFn, err
	}
	if r.Sealed == true {
		return nil, "", deferFn, errors.New("Failed to unseal Vault")
	}
	log.Debug("Unsealed")

	vault.Client.SetToken(token)

	hr := &HealthResponse{Standby: true}
	for ; hr.Standby; hr, _ = getHealthStatus(vault.Client) {
		time.Sleep(100 * time.Millisecond)
	}

	return &vault, token, deferFn, nil
}

type healthStatus struct {
	initialized bool `json:"initialized,omitempty"`
	sealed      bool `json:"sealed,omitempty"`
	standby     bool `json:"standby,omitempty"`
}

type HealthResponse struct {
	Initialized     bool `json:"initialized"`
	Sealed          bool `json:"sealed"`
	Standby         bool `json:"standby"`
	Server_time_utc int  `json:"server_time_utc"`
}

func getHealthStatus(vault *vaultapi.Client) (*HealthResponse, error) {
	r := vault.NewRequest("GET", "/v1/sys/health")
	if err := r.SetJSONBody(struct{}{}); err != nil {
		return nil, err
	}

	resp, err := vault.RawRequest(r)
	if err != nil {
		log.Errorf("err: %s, resp status: %d", err, resp.StatusCode)
		// TODO: 429 result is expected
		return nil, err
	}
	defer resp.Body.Close()

	result := HealthResponse{
		Initialized: false,
		Sealed:      true,
		Standby:     true,
	}
	resp.DecodeJSON(&result)
	log.Debugf("Health status: %#v", result)

	return &result, err
}
