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

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/util/codecs"
)

var (
	resetParameterArg string
)

func init() {
	resetCmd.Flags().StringVarP(&resetParameterArg, "parameter", "p", "", "Parameter to reset")
	resetCmd.MarkFlagRequired("parameter")

	rootCmd.AddCommand(resetCmd)
}

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset the specified parameter to its default (delete from config.json)",
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

			defaults := config.GetDefaultLocal()
			cfg, err = copyObjectProperty(cfg, defaults, resetParameterArg)
			if err != nil {
				reportWarnf("Error resetting property '%s' - %s", resetParameterArg, err)
				anyError = true
				return
			}

			file := filepath.Join(dataDir, config.ConfigFilename)
			err = codecs.SaveNonDefaultValuesToFile(file, cfg, defaults, nil, true)
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

func copyObjectProperty(object config.Local, defaultObject config.Local, property string) (config.Local, error) {
	v := reflect.ValueOf(&object)
	f := v.Elem().FieldByName(property)

	if !f.IsValid() {
		return object, fmt.Errorf("unknown property named '%s'", property)
	}

	vDefault := reflect.ValueOf(defaultObject)
	valDefault := reflect.Indirect(vDefault)
	fDefault := valDefault.FieldByName(property)

	if !fDefault.IsValid() {
		return object, fmt.Errorf("unknown property named '%s'", property)
	}

	f.Set(fDefault)
	return object, nil
}
