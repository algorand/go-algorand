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
	"runtime"

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

func EnableP2PLogging(log logging.Logger, l logging.Level) {
	core := loggingCore{
		log:   log,
		level: l,
	}
	for p2pLevel, logLevel := range levelsMap {
		if logLevel == l {
			p2plogging.SetAllLoggers(p2plogging.LogLevel(p2pLevel))
			break
		}
	}
	p2plogging.SetPrimaryCore(&core)
}

func (c *loggingCore) Enabled(l zapcore.Level) bool {
	return c.log.IsLevelEnabled(c.level)
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
	event = event.WithFields(logrus.Fields{
		"file": e.Caller.File,
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
