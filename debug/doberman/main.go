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

// doberman will tell you when there's something wrong with the system
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gen2brain/beeep"
)

const mtbNotify = 1 * time.Second
const retireIn = 100 * time.Millisecond

var tfname string

var testing = flag.Bool("test", false, "test doberman by sending a notification")
var filename = flag.String("file", "", "name of log file")

func notify(title string, body string) {
	err := beeep.Notify(title, body, tfname)
	if err != nil {
		panic(err)
	}
}

func main() {
	var err error

	flag.Parse()
	if !*testing && *filename == "" {
		fmt.Println("need log file name")
		return
	}

	// write logo
	tf, err := ioutil.TempFile("", "algorand-logo.png")
	tfname = tf.Name()
	defer func() {
		time.Sleep(retireIn)
		os.Remove(tfname)
	}()
	_, err = tf.Write(logo)
	if err != nil {
		panic(err)
	}

	if *testing {
		notify("doberman: TESTING", "woof woof woof")
		return
	}

	var input io.ReadCloser
	cmd := exec.Command("tail", "-F", *filename)
	input, err = cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		var obj map[string]interface{}
		line := scanner.Text()
		dec := json.NewDecoder(strings.NewReader(line))
		err := dec.Decode(&obj)
		if err != nil {
			panic(err)
		}

		if !(obj["level"] == "warning" || obj["level"] == "error" || obj["level"] == "fatal") {
			continue
		}

		fmt.Println(line)
		str := fmt.Sprintf("doberman: %v", obj["level"])
		notify(str, obj["msg"].(string))

		time.Sleep(mtbNotify) // throttling
	}
}
