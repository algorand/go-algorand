// Copyright (C) 2019-2024 Algorand, Inc.
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

// This package implement a zap.Core in order to wrap lip2p logger into algod's logger.

package p2p

import (
	"errors"
	"runtime"
	"strings"

	p2plogging "github.com/ipfs/go-log/v2"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap/zapcore"

	"github.com/algorand/go-algorand/logging"
)

// var levelsMap = map[logging.Level]zapcore.Level{
// 	logging.Debug: zapcore.DebugLevel,
// 	logging.Info:  zapcore.InfoLevel,
// 	logging.Warn:  zapcore.WarnLevel,
// 	logging.Error: zapcore.ErrorLevel,
// 	logging.Fatal: zapcore.FatalLevel,
// 	logging.Panic: zapcore.PanicLevel,
// }

var levelsMap = map[zapcore.Level]logging.Level{
	zapcore.DebugLevel: logging.Debug,
	zapcore.InfoLevel:  logging.Info,
	zapcore.WarnLevel:  logging.Warn,
	zapcore.ErrorLevel: logging.Error,
	zapcore.FatalLevel: logging.Fatal,
	zapcore.PanicLevel: logging.Panic,
}

// loggingCore implements zapcore.Core
type loggingCore struct {
	log    logging.Logger
	level  logging.Level
	fields []zapcore.Field
	zapcore.Core
}

// ErrInvalidLogLevel is returned when an invalid log level is provided.
var ErrInvalidLogLevel = errors.New("invalid log level")

// EnableP2PLogging enables libp2p logging into the provided logger with the provided level.
func EnableP2PLogging(log logging.Logger, l logging.Level) error {
	core := loggingCore{
		log:   log,
		level: l,
	}
	err := SetP2PLogLevel(l)
	if err != nil {
		return err
	}
	p2plogging.SetPrimaryCore(&core)
	return nil
}

// SetP2PLogLevel sets the log level for libp2p logging.
func SetP2PLogLevel(l logging.Level) error {
	var seen bool
	for p2pLevel, logLevel := range levelsMap {
		if logLevel == l {
			p2plogging.SetAllLoggers(p2plogging.LogLevel(p2pLevel))
			seen = true
			break
		}
	}
	if !seen {
		return ErrInvalidLogLevel
	}
	return nil
}

func (c *loggingCore) Enabled(l zapcore.Level) bool {
	level := levelsMap[l]
	return c.log.IsLevelEnabled(level)
}

func (c *loggingCore) With(fields []zapcore.Field) zapcore.Core {
	return &loggingCore{
		log:    c.log,
		level:  c.level,
		fields: append(c.fields, fields...),
	}
}

func (c *loggingCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *loggingCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	allFields := append(c.fields, fields...)
	loggingFields := make(logging.Fields, len(allFields))

	for _, f := range allFields {
		if len(f.String) > 0 {
			loggingFields[f.Key] = f.String
		} else if f.Interface != nil {
			loggingFields[f.Key] = f.Interface
		} else {
			loggingFields[f.Key] = f.Integer
		}
	}
	event := c.log.WithFields(loggingFields).With("libp2p", e.LoggerName)
	file := e.Caller.File
	slash := strings.LastIndex(file, "/")
	file = file[slash+1:]
	event = event.WithFields(logrus.Fields{
		"file": file,
		"line": e.Caller.Line,
	})
	if function := runtime.FuncForPC(e.Caller.PC); function != nil {
		event = event.With("function", function.Name())
	}
	event.Entry().Log(logrus.Level(levelsMap[e.Level]), e.Message)
	return nil
}

func (c *loggingCore) Sync() error {
	return nil
}
