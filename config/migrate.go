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
	"time"
)

//go:generate $GOROOT/bin/go run ./defaultsGenerator/defaultsGenerator.go -h ../scripts/LICENSE_HEADER -p config -o ./local_defaults.go -j ../installer/config.json.example -t ../test/testdata/configs/config-v%d.json
//go:generate $GOROOT/bin/go fmt local_defaults.go

// AutogenLocal - this variable is the "input" for the config default generator which automatically updates the above defaultLocal variable.
// it's implemented in ./config/defaults_gen.go, and should be the only "consumer" of this exported variable
var AutogenLocal = GetVersionedDefaultLocalConfig(getLatestConfigVersion())

func migrate(cfg Local, explicitFields map[string]interface{}) (newCfg Local, err error) {
	newCfg = cfg
	latestConfigVersion := getLatestConfigVersion()

	if cfg.Version > latestConfigVersion {
		err = fmt.Errorf("unexpected config version: %d", cfg.Version)
		return
	}

	for {
		if newCfg.Version == latestConfigVersion {
			break
		}
		defaultCurrentConfig := GetVersionedDefaultLocalConfig(newCfg.Version)
		localType := reflect.TypeOf(Local{})
		nextVersion := newCfg.Version + 1
		for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
			field := localType.Field(fieldNum)
			nextVersionDefaultValue, hasTag := reflect.StructTag(field.Tag).Lookup(fmt.Sprintf("version[%d]", nextVersion))
			if !hasTag {
				continue
			}

			// Check if this field was explicitly set in the config file
			// If it was, skip migration for this field to preserve user intent
			if _, wasExplicitlySet := explicitFields[field.Name]; wasExplicitlySet && field.Name != "Version" {
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

// matchDefaultVsMap checks if the config file is just a full dump of default values at some version
func matchDefaultVsMap(vcfg reflect.Value, explicitFields map[string]interface{}, version uint32) bool {
	extraFields := 0
	structFields := vcfg.NumField()

	// special handling for explicit version values from a config file:
	// version 1-10: these version are legacy and we do not apply any special handling for them.
	//     basically because these older config files were hand-written (not generated) and miss fields
	//     so that return true like it matches defaults so that apply the original migration logic.
	// version 0, 11-last: apply the following logic:
	//     if a config file (explicitFields) has all the fields set to default values matching to vcfg
	//     then we consider it a full dump of the default config for that version => return true
	//     and the original migration logic will apply.
	//     (note, a config file might have extra fields that not in Local definition anymore so ignore them)
	//     if a config file has some fields set to non-default values, then return false indication the
	//     config file is not a full dump of the default config for that version.
	if version >= 1 && version <= 10 {
		return true
	}

	for fieldName, fieldValue := range explicitFields {
		if fieldName == "Version" {
			continue
		}
		if !vcfg.FieldByName(fieldName).IsValid() {
			// some older configs may have fields that do not exist in the current version of the config.
			extraFields++
			continue
		}

		switch vcfg.FieldByName(fieldName).Kind() {
		case reflect.Map, reflect.Array:
			// do nothing, map/array values not supported in this function
		case reflect.Bool:
			if vcfg.FieldByName(fieldName).Bool() != fieldValue.(bool) {
				return false
			}
		case reflect.Int, reflect.Int32, reflect.Int64:
			if vcfg.FieldByName(fieldName).Int() != int64(fieldValue.(float64)) {
				return false
			}
		case reflect.Uint, reflect.Uint32, reflect.Uint64:
			if vcfg.FieldByName(fieldName).Uint() != uint64(fieldValue.(float64)) {
				return false
			}
		case reflect.String:
			if vcfg.FieldByName(fieldName).String() != fieldValue.(string) {
				return false
			}
		default:
			panic(fmt.Sprintf("unsupported data type (%s) encountered when reflecting on config.Local field %s", vcfg.FieldByName(fieldName).Kind(), fieldName))
		}
	}
	// now make sure that all structFields are accounted for in the explicitFields map
	return structFields == len(explicitFields)-extraFields
}

func getLatestConfigVersion() uint32 {
	localType := reflect.TypeOf(Local{})
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

// getVersionedLocalDefinitions returns an array of reflect.Type definitions for Local struct
// where each index corresponds to a version and contains only fields defined in that version
// with their appropriate default values as struct tags.
func getVersionedLocalDefinitions() []reflect.Type {
	localType := reflect.TypeOf(Local{})
	latestVersion := getLatestConfigVersion()

	// Create array to hold type definitions for each version
	versionTypes := make([]reflect.Type, latestVersion+1)

	for version := uint32(0); version <= latestVersion; version++ {
		var fields []reflect.StructField

		for fieldNum := 0; fieldNum < localType.NumField(); fieldNum++ {
			field := localType.Field(fieldNum)

			// Check if this field exists in the current version
			fieldDefaultValue, hasVersionTag := getFieldDefaultForVersion(field, version)
			if !hasVersionTag {
				continue
			}

			// Create new field with updated tag containing only the default value for this version
			newField := reflect.StructField{
				Name:      field.Name,
				Type:      field.Type,
				Tag:       reflect.StructTag(fmt.Sprintf(`default:"%s"`, fieldDefaultValue)),
				PkgPath:   field.PkgPath,
				Anonymous: field.Anonymous,
				Offset:    field.Offset,
				Index:     field.Index,
			}

			fields = append(fields, newField)
		}

		// Create struct type for this version
		versionTypes[version] = reflect.StructOf(fields)
	}

	return versionTypes
}

// getFieldDefaultForVersion returns the default value for a field at a specific version
// and whether the field exists in that version
func getFieldDefaultForVersion(field reflect.StructField, version uint32) (string, bool) {
	// Look for the highest version tag that is <= the requested version
	var latestValue string
	var hasAnyVersion bool

	for v := uint32(0); v <= version; v++ {
		if value, hasTag := reflect.StructTag(field.Tag).Lookup(fmt.Sprintf("version[%d]", v)); hasTag {
			latestValue = value
			hasAnyVersion = true
		}
	}

	return latestValue, hasAnyVersion
}

// getVersionedLocalInstance creates an instance of Local struct for a specific version
// with only fields that exist in that version set to their default values
func getVersionedLocalInstance(version uint32) reflect.Value {
	versionTypes := getVersionedLocalDefinitions()
	if version >= uint32(len(versionTypes)) {
		return reflect.Value{}
	}

	// Create instance of the versioned type
	versionType := versionTypes[version]
	instance := reflect.New(versionType).Elem()

	// Set default values from tags
	for i := 0; i < instance.NumField(); i++ {
		field := instance.Field(i)
		fieldType := versionType.Field(i)

		if defaultValue, ok := fieldType.Tag.Lookup("default"); ok && defaultValue != "" {
			setFieldValue(field, defaultValue)
		}
	}

	return instance
}

// setFieldValue sets a reflect.Value to the string representation of its default value
func setFieldValue(field reflect.Value, value string) {
	if !field.CanSet() {
		return
	}

	switch field.Kind() {
	case reflect.Bool:
		if boolVal, err := strconv.ParseBool(value); err == nil {
			field.SetBool(boolVal)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Type() == reflect.TypeOf(time.Duration(0)) {
			if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
				field.SetInt(intVal)
			}
		} else {
			if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
				field.SetInt(intVal)
			}
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if uintVal, err := strconv.ParseUint(value, 10, 64); err == nil {
			field.SetUint(uintVal)
		}
	case reflect.String:
		field.SetString(value)
	case reflect.Map:
		if value == "" {
			field.Set(reflect.MakeMap(field.Type()))
		}
	case reflect.Slice:
		if value == "" {
			field.Set(reflect.MakeSlice(field.Type(), 0, 0))
		}
	}
}

// var versionedDefaultLocal []reflect.Value
var versionedDefaultLocal = map[uint32]reflect.Value{}

// // build dynamic config struct definition based on version tags in Local struct
// func init() {
// 	// Initialize versioned definitions on package load
// 	for version := uint32(0); version <= getLatestConfigVersion(); version++ {
// 		versionedDefaultLocal = append(versionedDefaultLocal, getVersionedLocalInstance(version))
// 	}
// }
