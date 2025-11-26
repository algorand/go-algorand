// Copyright (C) 2019-2025 Algorand, Inc.
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

//go:generate $GOROOT/bin/go run ./defaultsGenerator/defaultsGenerator.go -h ../scripts/LICENSE_HEADER -p config -o ./local_defaults.go -j ../installer/config.json.example -t ../test/testdata/configs/config-v%d.json
//go:generate $GOROOT/bin/go fmt local_defaults.go

// AutogenLocal - this variable is the "input" for the config default generator which automatically updates the above defaultLocal variable.
// it's implemented in ./config/defaults_gen.go, and should be the only "consumer" of this exported variable
var AutogenLocal = GetVersionedDefaultLocalConfig(getLatestConfigVersion())

// MigrationResult represents a single field migration from one version to another
type MigrationResult struct {
	FieldName              string
	OldVersion, NewVersion uint32
	OldValue, NewValue     any
}

func migrate(cfg Local) (newCfg Local, migrations []MigrationResult, err error) {
	newCfg = cfg
	originalVersion := cfg.Version
	latestConfigVersion := getLatestConfigVersion()

	if cfg.Version > latestConfigVersion {
		err = fmt.Errorf("unexpected config version: %d", cfg.Version)
		return
	}

	// Track which fields were migrated during this entire process
	migrationResults := make(map[string]MigrationResult)

	for {
		if newCfg.Version == latestConfigVersion {
			break
		}
		defaultCurrentConfig := GetVersionedDefaultLocalConfig(newCfg.Version)
		localType := reflect.TypeFor[Local]()
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
					if m, exists := migrationResults[field.Name]; exists {
						m.NewValue = boolVal
						m.NewVersion = nextVersion
						migrationResults[field.Name] = m
					} else {
						oldValue := reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Bool()
						migrationResults[field.Name] = MigrationResult{FieldName: field.Name, OldVersion: originalVersion, NewVersion: nextVersion, OldValue: oldValue, NewValue: boolVal}
					}
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
					if m, exists := migrationResults[field.Name]; exists {
						m.NewValue = intVal
						m.NewVersion = nextVersion
						migrationResults[field.Name] = m
					} else {
						oldValue := reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Int()
						migrationResults[field.Name] = MigrationResult{FieldName: field.Name, OldVersion: originalVersion, NewVersion: nextVersion, OldValue: oldValue, NewValue: intVal}
					}
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
					if m, exists := migrationResults[field.Name]; exists {
						m.NewValue = uintVal
						m.NewVersion = nextVersion
						migrationResults[field.Name] = m
					} else {
						oldValue := reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Uint()
						migrationResults[field.Name] = MigrationResult{FieldName: field.Name, OldVersion: originalVersion, NewVersion: nextVersion, OldValue: oldValue, NewValue: uintVal}
					}
				}
			case reflect.String:
				if reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).String() == reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).String() {
					// we're skipping the error checking here since we already tested that in the unit test.
					reflect.ValueOf(&newCfg).Elem().FieldByName(field.Name).SetString(nextVersionDefaultValue)
					if m, exists := migrationResults[field.Name]; exists {
						m.NewValue = nextVersionDefaultValue
						m.NewVersion = nextVersion
						migrationResults[field.Name] = m
					} else {
						oldValue := reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).String()
						migrationResults[field.Name] = MigrationResult{FieldName: field.Name, OldVersion: originalVersion, NewVersion: nextVersion, OldValue: oldValue, NewValue: nextVersionDefaultValue}
					}
				}
			default:
				panic(fmt.Sprintf("unsupported data type (%s) encountered when reflecting on config.Local datatype %s", reflect.ValueOf(&defaultCurrentConfig).Elem().FieldByName(field.Name).Kind(), field.Name))
			}
		}
	}

	// Only return migrations where the value actually changed
	for _, m := range migrationResults {
		if m.FieldName != "Version" && m.OldValue != m.NewValue {
			migrations = append(migrations, m)
		}
	}

	return
}

func getLatestConfigVersion() uint32 {
	localType := reflect.TypeFor[Local]()
	versionField, found := localType.FieldByName("Version")
	if !found {
		return 0
	}
	version := uint32(0)
	for {
		_, hasTag := reflect.StructTag(versionField.Tag).Lookup(fmt.Sprintf("version[%d]", version+1))
		if !hasTag {
			return version
		}
		version++
	}
}

// GetVersionedDefaultLocalConfig returns the default config for the given version.
func GetVersionedDefaultLocalConfig(version uint32) (local Local) {
	if version > 0 {
		local = GetVersionedDefaultLocalConfig(version - 1)
	}
	// apply version specific changes.
	localType := reflect.TypeFor[Local]()
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
