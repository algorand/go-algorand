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
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	head = iota
	maintext
	paramtext
)

func extractHelpFromFile(filename string) (helptext string, shorthelp string, params paramSet, err error) {
	defer func() {
		if err == nil {

			for last := string(helptext[len(helptext)-1]); last == "\n"; last = string(helptext[len(helptext)-1]) {
				helptext = helptext[:len(helptext)-1]
			}
		}
	}()

	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	state := head
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if state == head {
			if strings.HasPrefix(scanner.Text(), "//") {
				state = maintext
			} else if scanner.Text() != "" {
				break
			}
		}

		if state == maintext {
			if !strings.HasPrefix(scanner.Text(), "//") {
				break
			}
			if scanner.Text() == "// Parameters:" {
				state = paramtext
				continue
			}
			if scanner.Text() == "//" {
				helptext += "\n"
			} else {
				helptext += scanner.Text()[3:] + "\n"
				if shorthelp == "" {
					shorthelp = scanner.Text()[3:]
				}
			}
		}

		if state == paramtext {
			if !strings.HasPrefix(scanner.Text(), "//") {
				break
			}
			if !strings.HasPrefix(scanner.Text(), "//  - ") {
				err = fmt.Errorf("parameter line not correctly formed")
			}

			fields := strings.Split(scanner.Text(), ":")
			name := fields[0][len("//  - "):]
			if string(name[len(name)-1]) == ":" {
				name = name[:len(name)-1]
			} else {
				fields := strings.Split(name, " ")
				name = fields[0]
			}
			descr := fields[len(fields)-1][1:]
			params.params = append(params.params, param{name: name, descr: descr})
		}
	}

	err = scanner.Err()
	return
}
