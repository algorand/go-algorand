// Copyright (C) 2019-2021 Algorand, Inc.
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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/util/codecs"
)

var (
	setParameterArg string
	setValueArg     string
)

func init() {
	setCmd.Flags().StringVarP(&setParameterArg, "parameter", "p", "", "Parameter to update")
	setCmd.Flags().StringVarP(&setValueArg, "value", "v", "", "Value to set")
	setCmd.MarkFlagRequired("parameter")
	setCmd.MarkFlagRequired("value")

	rootCmd.AddCommand(setCmd)
}

var setCmd = &cobra.Command{
	Use:   "set",
	Short: "Update the current value for the specified parameter",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		anyError := false
		onDataDirs(func(dataDir string) {
			cfg, err := config.LoadConfigFromDisk(dataDir)
			if err != nil && !os.IsNotExist(err) {
				reportWarnf("Error loading config file from '%s'", dataDir)
				anyError = true
				return
			}

			cfg, err = setObjectProperty(cfg, setParameterArg, setValueArg)
			if err != nil {
				reportWarnf("Error setting property '%s' -> %s - %s", setParameterArg, setValueArg, err)
				anyError = true
				return
			}

			file := filepath.Join(dataDir, config.ConfigFilename)
			err = codecs.SaveNonDefaultValuesToFile(file, cfg, config.GetDefaultLocal(), nil, true)
			if err != nil {
				reportWarnf("Error saving updated config file '%s' - %s", file, err)
				anyError = true
				return
			}
		})
		if anyError {
			os.Exit(1)
		}
	},
}

func setObjectProperty(object config.Local, property string, value string) (config.Local, error) {
	v := reflect.ValueOf(&object)
	f := v.Elem().FieldByName(property)

	if !f.IsValid() {
		return object, fmt.Errorf("unknown property named '%s'", property)
	}

	err := setFieldValue(f, value)
	return object, err
}

func setFieldValue(field reflect.Value, value string) error {
	switch k := field.Kind(); k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		// NOTE: We do not enforce bitsize
		field.SetInt(val)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		// NOTE: We do not enforce bitsize
		field.SetUint(val)

	case reflect.String:
		field.SetString(value)

	case reflect.Float32, reflect.Float64:
		val, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return err
		}
		// NOTE: We do not enforce bitsize
		field.SetFloat(val)

	case reflect.Bool:
		switch value {
		case "t", "true", "True", "TRUE", "1":
			field.SetBool(true)
		case "f", "false", "False", "FALSE", "0":
			field.SetBool(false)
		default:
			return fmt.Errorf("could not parse value %#v as bool", value)
		}
	default:
		return fmt.Errorf("unsupported parameter type '%s' - unable to set value", k)
	}

	return nil
}
