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

// algotmpl is a command-line tool which provides documentation and fills
// out templates for users.
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const tmplSuffix = ".teal.tmpl"

var templateDir string
var dummyHelp bool

func reportErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func init() {
	dummyCmd.Flags().BoolVarP(&dummyHelp, "help", "h", false, "help for algotmpl")
	dummyCmd.PersistentFlags().StringVarP(&templateDir, "directory", "d", "", "directory of templates")
	dummyCmd.MarkPersistentFlagRequired("directory")

	// suppress help text in case we are provided a directory
	hf := dummyCmd.HelpFunc()
	dummyCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if templateDir != "" {
			return
		}
		hf(cmd, args)
	})

	rootCmd.PersistentFlags().StringVarP(&templateDir, "directory", "d", "", "directory of templates")
	rootCmd.MarkPersistentFlagRequired("directory")
}

var rootCmd = &cobra.Command{
	Use:   "algotmpl",
	Short: "Interact with Algorand templates.",
	Long:  `'algotmpl' is a command for interacting with Algorand templates`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
		os.Exit(1)
	},
}

var dummyCmd = &cobra.Command{
	Use:   "algotmpl",
	Short: "Interact with Algorand templates.",
	Long:  `'algotmpl' is a command for interacting with Algorand templates`,
	Run: func(cmd *cobra.Command, args []string) {
		// pass
	},

	FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
}

func main() {
	if err := dummyCmd.Execute(); err != nil {
		reportErrorf(err.Error())
	}

	if dummyHelp && templateDir == "" {
		// help was printed; do not proceed
		return
	}

	err := initCommandsFromDir(templateDir)
	if err != nil {
		reportErrorf(err.Error())
	}

	if err := rootCmd.Execute(); err != nil {
		reportErrorf(err.Error())
	}
}

type paramSet struct {
	params []param
	vars   map[string]*string
}

type param struct {
	name, descr string
}

func initCommandsFromDir(dirname string) error {
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		return err
	}
	var fnames []string
	for _, h := range files {
		fullname := h.Name()
		if !strings.HasSuffix(fullname, tmplSuffix) {
			continue
		}
		tmplname := fullname[:len(fullname)-len(tmplSuffix)]
		fnames = append(fnames, tmplname)
	}

	if len(fnames) == 0 {
		return fmt.Errorf("no %s files found in '%s'; are you sure templates exist there?", tmplSuffix, dirname)
	}

	helptext := make([]string, len(fnames))
	shorthelp := make([]string, len(fnames))
	params := make([]paramSet, len(fnames))
	filedata := make([]string, len(fnames))

	for i, fname := range fnames {
		var err error
		fullpath := filepath.Join(dirname, fname+tmplSuffix)
		helptext[i], shorthelp[i], params[i], err = extractHelpFromFile(fullpath)
		if err != nil {
			return err
		}
		data, err := ioutil.ReadFile(fullpath)
		if err != nil {
			return err
		}
		filedata[i] = string(data)
	}

	for i := range fnames {
		vars := make(map[string]*string)
		progtext := filedata[i]

		subCmd := &cobra.Command{
			Use:   fnames[i],
			Short: shorthelp[i],
			Long:  helptext[i],
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, args []string) {
				for k, v := range vars {
					progtext = strings.ReplaceAll(progtext, k, *v)
				}
				if strings.Contains(progtext, "TMPL_") {
					reportErrorf("template %s fails to document all parameters", fnames[i])
				}
				fmt.Println(progtext)
			},
		}

		for _, param := range params[i].params {
			var alloc string
			vars[param.name] = &alloc
			cmdName := strings.ToLower(param.name[len("TMPL_"):])
			subCmd.Flags().StringVar(vars[param.name], cmdName, "", param.descr)
			subCmd.MarkFlagRequired(cmdName)
		}
		pp := params[i]
		pp.vars = vars
		params[i] = pp

		rootCmd.AddCommand(subCmd)
	}
	return nil
}
