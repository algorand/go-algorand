// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"fmt"
	"reflect"
	"strconv"
)

//go:generate $GOROOT/bin/go run ./defaultsGenerator/defaultsGenerator.go -h ../scripts/LICENSE_HEADER -p config -o ./local_defaults.go -j ../installer/config.json.example -t local
//go:generate $GOROOT/bin/go fmt local_defaults.go

//go:generate $GOROOT/bin/go run ./defaultsGenerator/defaultsGenerator.go -h ../scripts/LICENSE_HEADER -p config -o ./relay_defaults.go -j ../installer/config.json.relay-example -t relay
//go:generate $GOROOT/bin/go fmt relay_defaults.go

// AutogenLocal - this variable is the "input" for the config default generator which automatically updates the above defaultLocal variable.
// it's implemented in ./config/defaults_gen.go, and should be the only "consumer" of this exported variable
var AutogenLocal = getVersionedDefaultLocalConfig(getLatestConfigVersion(Local{}))

// AutogenRelay - this variable is the "input" for the config default generator. It separately generates the default
// values for the Relay config.
var AutogenRelay = getVersionedDefaultRelayConfig(getLatestConfigVersion(Relay{}))

func migrate(cfg Local) (newCfg Local, err error) {
	newCfg = cfg
	latestConfigVersion := getLatestConfigVersion(Local{})

	if cfg.Version > latestConfigVersion {
		err = fmt.Errorf("unexpected config version: %d", cfg.Version)
		return
	}

	for {
		if newCfg.Version == latestConfigVersion {
			break
		}
		defaultCurrentConfig := getVersionedDefaultLocalConfig(newCfg.Version)
		localType := reflect.TypeOf(Local{})
		nextVersion := newCfg.Version + 1
		for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
			field := localType.Field(fieldNum)
			nextVersionDefaultValue, hasTag := reflect.StructTag(field.Tag).Lookup(fmt.Sprintf("version[%d]", nextVersion))
			if !hasTag {
				continue
			}
			if nextVersionDefaultValue == "" {
				switch reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Kind() {
				case reflect.Map:
					// if the current implementation have a nil value, use the same value as
					// the default one ( i.e. empty map rather than nil map)
					if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Len() == 0 {
						reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Set(reflect.MakeMap(field.Type))
					}
				case reflect.Array:
					// if the current implementation have a nil value, use the same value as
					// the default one ( i.e. empty slice rather than nil slice)
					if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Len() == 0 {
						reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Set(reflect.MakeSlice(field.Type, 0, 0))
					}
				default:
				}
				continue
			}
			// we have found a field that has a new value for this new version. See if the current configuration value for that
			// field is identical to the default configuration for the field.
			switch reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Kind() {
			case reflect.Bool:
				if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Bool() == reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Bool() {
					// we're skipping the error checking here since we already tested that in the unit test.
					boolVal, _ := strconv.ParseBool(nextVersionDefaultValue)
					reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).SetBool(boolVal)
				}
			case reflect.Int32:
				fallthrough
			case reflect.Int:
				fallthrough
			case reflect.Int64:
				if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Int() == reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Int() {
					// we're skipping the error checking here since we already tested that in the unit test.
					intVal, _ := strconv.ParseInt(nextVersionDefaultValue, 10, 64)
					reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).SetInt(intVal)
				}
			case reflect.Uint32:
				fallthrough
			case reflect.Uint:
				fallthrough
			case reflect.Uint64:
				if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).Uint() == reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Uint() {
					// we're skipping the error checking here since we already tested that in the unit test.
					uintVal, _ := strconv.ParseUint(nextVersionDefaultValue, 10, 64)
					reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).SetUint(uintVal)
				}
			case reflect.String:
				if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).String() == reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).String() {
					// we're skipping the error checking here since we already tested that in the unit test.
					reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).SetString(nextVersionDefaultValue)
				}
			default:
				panic(fmt.Sprintf("unsupported data type (%s) encountered when reflecting on config.Local datatype %s", reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Kind(), field.Name))
			}
		}
	}
	return
}

func getLatestConfigVersion(cfg interface{}) uint32 {
	var versionField reflect.StructField
	var found bool
	switch cfg.(type) {
	case Local:
		localType := reflect.TypeOf(Local{})
		versionField, found = localType.FieldByName("Version")
	case Relay:
		relayType := reflect.TypeOf(Relay{})
		versionField, found = relayType.FieldByName("Version")
	default:
		return 0
	}
	if !found {
		return 0
	}
	version := uint32(0)
	for {
		_, hasTag := versionField.Tag.Lookup(fmt.Sprintf("version[%d]", version+1))
		if !hasTag {
			return version
		}
		version++
	}
}

func getVersionedDefaultRelayConfig(version uint32) (relay Relay) {
	if version < 0 {
		return
	}
	if version > 0 {
		relay = getVersionedDefaultRelayConfig(version - 1)
	}
	// apply version specific changes.
	localType := reflect.TypeOf(relay)
	for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
		field := localType.Field(fieldNum)
		versionDefaultValue, hasTag := reflect.StructTag(field.Tag).Lookup(fmt.Sprintf("version[%d]", version))
		if !hasTag {
			continue
		}
		if versionDefaultValue == "" {
			// set the default field value in case it's a map/array so we won't have nil ones.
			switch reflect.ValueOf(&relay).Elem().FieldByName(field.Name).Kind() {
			case reflect.Map:
				reflect.ValueOf(&relay).Elem().FieldByName(field.Name).Set(reflect.MakeMap(field.Type))
			case reflect.Array:
				reflect.ValueOf(&relay).Elem().FieldByName(field.Name).Set(reflect.MakeSlice(field.Type, 0, 0))
			default:
			}
			continue
		}
		switch reflect.ValueOf(&relay).Elem().FieldByName(field.Name).Kind() {
		case reflect.Bool:
			boolVal, err := strconv.ParseBool(versionDefaultValue)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&relay).Elem().FieldByName(field.Name).SetBool(boolVal)

		case reflect.Int32:
			intVal, err := strconv.ParseInt(versionDefaultValue, 10, 32)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&relay).Elem().FieldByName(field.Name).SetInt(intVal)
		case reflect.Int:
			fallthrough
		case reflect.Int64:
			intVal, err := strconv.ParseInt(versionDefaultValue, 10, 64)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&relay).Elem().FieldByName(field.Name).SetInt(intVal)

		case reflect.Uint32:
			uintVal, err := strconv.ParseUint(versionDefaultValue, 10, 32)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&relay).Elem().FieldByName(field.Name).SetUint(uintVal)
		case reflect.Uint:
			fallthrough
		case reflect.Uint64:
			uintVal, err := strconv.ParseUint(versionDefaultValue, 10, 64)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&relay).Elem().FieldByName(field.Name).SetUint(uintVal)
		case reflect.String:
			reflect.ValueOf(&relay).Elem().FieldByName(field.Name).SetString(versionDefaultValue)
		default:
			panic(fmt.Sprintf("unsupported data type (%s) encountered when reflecting on config.Local datatype %s", reflect.ValueOf(&relay).Elem().FieldByName(field.Name).Kind(), field.Name))
		}
	}
	return
}

func getVersionedDefaultLocalConfig(version uint32) (local Local) {
	if version < 0 {
		return
	}
	if version > 0 {
		local = getVersionedDefaultLocalConfig(version - 1)
	}
	// apply version specific changes.
	localType := reflect.TypeOf(local)
	for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
		field := localType.Field(fieldNum)
		versionDefaultValue, hasTag := reflect.StructTag(field.Tag).Lookup(fmt.Sprintf("version[%d]", version))
		if !hasTag {
			continue
		}
		if versionDefaultValue == "" {
			// set the default field value in case it's a map/array so we won't have nil ones.
			switch reflect.ValueOf(&local).Elem().FieldByName(field.Name).Kind() {
			case reflect.Map:
				reflect.ValueOf(&local).Elem().FieldByName(field.Name).Set(reflect.MakeMap(field.Type))
			case reflect.Array:
				reflect.ValueOf(&local).Elem().FieldByName(field.Name).Set(reflect.MakeSlice(field.Type, 0, 0))
			default:
			}
			continue
		}
		switch reflect.ValueOf(&local).Elem().FieldByName(field.Name).Kind() {
		case reflect.Bool:
			boolVal, err := strconv.ParseBool(versionDefaultValue)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&local).Elem().FieldByName(field.Name).SetBool(boolVal)

		case reflect.Int32:
			intVal, err := strconv.ParseInt(versionDefaultValue, 10, 32)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&local).Elem().FieldByName(field.Name).SetInt(intVal)
		case reflect.Int:
			fallthrough
		case reflect.Int64:
			intVal, err := strconv.ParseInt(versionDefaultValue, 10, 64)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&local).Elem().FieldByName(field.Name).SetInt(intVal)

		case reflect.Uint32:
			uintVal, err := strconv.ParseUint(versionDefaultValue, 10, 32)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&local).Elem().FieldByName(field.Name).SetUint(uintVal)
		case reflect.Uint:
			fallthrough
		case reflect.Uint64:
			uintVal, err := strconv.ParseUint(versionDefaultValue, 10, 64)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(&local).Elem().FieldByName(field.Name).SetUint(uintVal)
		case reflect.String:
			reflect.ValueOf(&local).Elem().FieldByName(field.Name).SetString(versionDefaultValue)
		default:
			panic(fmt.Sprintf("unsupported data type (%s) encountered when reflecting on config.Local datatype %s", reflect.ValueOf(&local).Elem().FieldByName(field.Name).Kind(), field.Name))
		}
	}
	return
}

// GetNonDefaultConfigValues takes a provided cfg and list of field names, and returns a map of all values in cfg
// that are not set to the default for the latest version.
func GetNonDefaultConfigValues(cfg Local, fieldNames []string) map[string]interface{} {
	defCfg := GetDefaultLocal()
	ret := make(map[string]interface{})

	for _, fieldName := range fieldNames {
		defField := reflect.ValueOf(defCfg).FieldByName(fieldName)
		if !defField.IsValid() {
			continue
		}
		cfgField := reflect.ValueOf(cfg).FieldByName(fieldName)
		if !cfgField.IsValid() {
			continue
		}
		if !reflect.DeepEqual(defField.Interface(), cfgField.Interface()) {
			ret[fieldName] = cfgField.Interface()
		}
	}
	return ret
}
