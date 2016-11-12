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

package config

import (
	"config2vault/log"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
)

// Config represents the configuration information.
type Config struct {
	Rules string `json:"rules,omitempty"`
	Url   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`

	CaFile   string `json:"ca_file,omitempty"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

// Conf contains the initialized configuration struct
var Conf Config

var configPath string

func init() {
	flag.StringVar(&configPath, "config", "./config.json", "path to the config file")
}

func ReadConfig() error {
	// Get the config file
	configFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.New("Cant load config file at path: " + configPath)
	}
	err = json.Unmarshal(configFile, &Conf)
	if err != nil {
		log.Errorf("Failed to load config file: %v", err)
	}

	return nil
}
