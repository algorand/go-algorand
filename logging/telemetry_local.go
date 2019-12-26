// Copyright (C) 2019 Algorand, Inc.
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

package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type localFileHook struct {
	path string
	out  io.Writer
}

func createLocalFileTelemetryHook(uri string) (hook logrus.Hook, err error) {
	xu, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if xu.Scheme != "file" {
		return nil, fmt.Errorf("bad attempt to create local telemetry with uri=%#v", uri)
	}
	return &localFileHook{path: xu.Path}, nil
}

var localFileLevels = []logrus.Level{
	logrus.PanicLevel,
	logrus.FatalLevel,
	logrus.ErrorLevel,
}

// implement logrus.Hook
func (lfh *localFileHook) Levels() []logrus.Level {
	return localFileLevels
}

// implement logrus.Hook
func (lfh *localFileHook) Fire(ent *logrus.Entry) error {
	out := make(map[string]interface{}, 4)
	out["Time"] = ent.Time.UTC().Format(time.RFC3339Nano)
	out["Level"] = strings.ToUpper(ent.Level.String())
	out["Message"] = ent.Message
	out["Data"] = ent.Data
	xj, err := json.Marshal(out)
	if err != nil {
		return err
	}
	xj = append(xj, '\n')
	if lfh.out == nil {
		var err error
		lfh.out, err = os.OpenFile(lfh.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			lfh.out = nil
			return err
		}
	}
	_, err = lfh.out.Write(xj)
	return err
}
