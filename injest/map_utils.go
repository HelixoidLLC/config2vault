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
	"encoding/json"
	"reflect"
	"strconv"
)

func getIntFromMap(m *map[string]interface{}, key string, defaultValue int) (result int) {
	if m == nil {
		return defaultValue
	}
	value, ok := (*m)[key]
	if !ok {
		return defaultValue
	}
	switch v := value.(type) {
	case json.Number:
		resultI, err := v.Int64()
		if err != nil {
			log.Errorf("Failed to convert '%s' value '%v' of type %s to int", key, value, reflect.TypeOf(value))
			return defaultValue
		}
		return int(resultI)
	case int:
		result, ok = value.(int)
		if !ok {
			log.Errorf("Failed to convert '%s' value '%v' of type %s to int", key, value, reflect.TypeOf(value))
			return defaultValue
		}
		return result
	}

	log.Errorf("Don't know how to convert '%s' value '%v' of type %s to int", key, value, reflect.TypeOf(value))
	return defaultValue
}

func getStringFromMap(m *map[string]interface{}, key string, defaultValue string) (result string) {
	if m == nil {
		return defaultValue
	}
	value, ok := (*m)[key]
	if !ok {
		return defaultValue
	}
	switch v := value.(type) {
	case json.Number:
		resultI, err := v.Int64()
		if err != nil {
			log.Errorf("Failed to convert '%s' value '%v' of type %s to string", key, value, reflect.TypeOf(value))
			return defaultValue
		}
		return strconv.FormatInt(resultI, 10)
	case string:
		result, ok = value.(string)
		if !ok {
			log.Errorf("Failed to convert '%s' value '%v' of type %s to string", key, value, reflect.TypeOf(value))
			return defaultValue
		}
		return result
	}

	log.Errorf("Don't know how to convert '%s' value '%v' of type %s to string", key, value, reflect.TypeOf(value))
	return defaultValue
}

func getStringArrayFromMap(m *map[string]interface{}, key string, defaultValue []string) (result []string) {
	if m == nil {
		return defaultValue
	}
	value, ok := (*m)[key]
	if !ok {
		return defaultValue
	}
	resultTmp, ok := value.([]interface{})
	result = make([]string, len(resultTmp))
	for i, v := range resultTmp {
		result[i] = v.(string)
	}
	if !ok {
		log.Errorf("Failed to convert '%s' value '%v' of type %s to []string", key, value, reflect.TypeOf(value))
		return defaultValue
	}
	return result
}

func getBoolFromMap(m *map[string]interface{}, key string, defaultValue bool) (result bool) {
	if m == nil {
		return defaultValue
	}
	value, ok := (*m)[key]
	if !ok {
		return defaultValue
	}
	result, ok = value.(bool)
	if !ok {
		log.Errorf("Failed to convert '%s' value '%v' of type %s to bool", key, value, reflect.TypeOf(value))
		return defaultValue
	}
	return result
}

func getStringMapInterfaceFromMap(m *map[string]interface{}, key string, defaultValue *map[string]interface{}) *map[string]interface{} {
	if m == nil {
		return defaultValue
	}
	value, ok := (*m)[key]
	if !ok {
		return defaultValue
	}
	var result map[string]interface{}
	switch value.(type) {
	case map[interface{}]interface{}:
		result = make(map[string]interface{})
		interface_map, ok := value.(map[interface{}]interface{})
		if !ok {
			log.Errorf("Failed to convert '%s' value '%v' of type %s to map[interface{}]interface{}", key, value, reflect.TypeOf(value))
			return defaultValue
		}
		for k, v := range interface_map {
			key, ok := k.(string)
			if !ok {
				log.Errorf("Failed to convert '%s' value '%v' of type %s to string", key, k, reflect.TypeOf(k))
				return defaultValue
			}
			result[key] = v
		}
	case map[string]interface{}:
		log.Debug("nothing")
		result = make(map[string]interface{})
	default:
		log.Errorf("Failed to convert '%s' value '%v' of type %s to map[interface{}]interface{}", key, value, reflect.TypeOf(value))
		return defaultValue
	}
	return &result
}

func stringArrayToStringMap(in *[]string) *map[string]interface{} {
	out := make(map[string]interface{})
	for _, s := range *in {
		out[s] = nil
	}
	return &out
}

func getStringMapFromInterfaceMapInterface(in map[interface{}]interface{}) map[string]string {
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

func getStringMapFromStringMapInterface(in map[string]interface{}) map[string]string {
	out := make(map[string]string)
	for key, value := range in {
		switch value := value.(type) {
		case string:
			out[key] = value
		}
	}
	return out
}