// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Changes from original
// - No more use of kingpin
// - No more Error Log writer
// - Extracted output setting from NewLogger
// - Added support for function name as an addition
// - Added support for WithFields
// - General refactoring
// - Added Testing
// - No general log which is not created by NewLogger
// - Added some base

/*
Example --
To log to the base logger
Base().Info("New wallet was created")

To log to a new logger
logger = NewLogger()
logger.Info("New wallet was created")
*/

package logging

import (
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/algorand/go-algorand/logging/telemetryspec"
)

// Level refers to the log logging level
type Level uint32

// Create a general Base logger
var (
	baseLogger Logger
)

const (
	// Panic Level level, highest level of severity. Logs and then calls panic with the
	// message passed to Debug, Info, ...
	Panic Level = iota
	// Fatal Level level. Logs and then calls `os.Exit(1)`. It will exit even if the
	// logging level is set to Panic.
	Fatal
	// Error Level level. Used for errors that should definitely be noted.
	// Commonly used for hooks to send errors to an error tracking service.
	Error
	// Warn Level level. Non-critical entries that deserve eyes.
	Warn
	// Info Level level. General operational entries about what's going on inside the
	// application.
	Info
	// Debug Level level. Usually only enabled when debugging. Very verbose logging.
	Debug
)

const stackPrefix = "[Stack]"

var once sync.Once

// Init needs to be called to ensure our logging has been initialized
func Init() {
	once.Do(func() {
		// By default, log to stderr (logrus's default), only warnings and above.
		baseLogger = NewLogger()
		baseLogger.SetLevel(Warn)
	})
}

func init() {
	Init()
}

// Fields maps logrus fields
type Fields = logrus.Fields

// Logger is the interface for loggers.
type Logger interface {
	// Debug logs a message at level Debug.
	Debug(...interface{})
	Debugln(...interface{})
	Debugf(string, ...interface{})

	// Info logs a message at level Info.
	Info(...interface{})
	Infoln(...interface{})
	Infof(string, ...interface{})

	// Warn logs a message at level Warn.
	Warn(...interface{})
	Warnln(...interface{})
	Warnf(string, ...interface{})

	// Error logs a message at level Error.
	Error(...interface{})
	Errorln(...interface{})
	Errorf(string, ...interface{})

	// Fatal logs a message at level Fatal.
	Fatal(...interface{})
	Fatalln(...interface{})
	Fatalf(string, ...interface{})

	// Panic logs a message at level Panic.
	Panic(...interface{})
	Panicln(...interface{})
	Panicf(string, ...interface{})

	// Add one key-value to log
	With(key string, value interface{}) Logger

	// WithFields logs a message with specific fields
	WithFields(Fields) Logger

	// Set the logging version (Info by default)
	SetLevel(Level)

	// Sets the output target
	SetOutput(io.Writer)

	// Sets the logger to JSON Format
	SetJSONFormatter()

	IsLevelEnabled(level Level) bool

	// source adds file, line and function fields to the event
	source() *logrus.Entry

	// Adds a hook to the logger
	AddHook(hook logrus.Hook)

	EnableTelemetry(cfg TelemetryConfig) error
	UpdateTelemetryURI(uri string) error
	GetTelemetryEnabled() bool
	GetTelemetryUploadingEnabled() bool
	Metrics(category telemetryspec.Category, metrics telemetryspec.MetricDetails, details interface{})
	Event(category telemetryspec.Category, identifier telemetryspec.Event)
	EventWithDetails(category telemetryspec.Category, identifier telemetryspec.Event, details interface{})
	StartOperation(category telemetryspec.Category, identifier telemetryspec.Operation) TelemetryOperation
	GetTelemetrySession() string
	GetTelemetryHostName() string
	GetInstanceName() string
	GetTelemetryURI() string
	CloseTelemetry()
}

type loggerState struct {
	telemetry *telemetryState
}

type logger struct {
	entry       *logrus.Entry
	loggerState *loggerState
}

func (l logger) With(key string, value interface{}) Logger {
	return logger{
		l.entry.WithField(key, value),
		l.loggerState,
	}
}

func (l logger) Debug(args ...interface{}) {
	l.source().Debug(args...)
}

func (l logger) Debugln(args ...interface{}) {
	l.source().Debugln(args...)
}

func (l logger) Debugf(format string, args ...interface{}) {
	l.source().Debugf(format, args...)
}

func (l logger) Info(args ...interface{}) {
	l.source().Info(args...)
}

func (l logger) Infoln(args ...interface{}) {
	l.source().Infoln(args...)
}

func (l logger) Infof(format string, args ...interface{}) {
	l.source().Infof(format, args...)
}

func (l logger) Warn(args ...interface{}) {
	l.source().Warn(args...)
}

func (l logger) Warnln(args ...interface{}) {
	l.source().Warnln(args...)
}

func (l logger) Warnf(format string, args ...interface{}) {
	l.source().Warnf(format, args...)
}

func (l logger) Error(args ...interface{}) {
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Error(args...)
}

func (l logger) Errorln(args ...interface{}) {
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Errorln(args...)
}

func (l logger) Errorf(format string, args ...interface{}) {
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Errorf(format, args...)
}

func (l logger) Fatal(args ...interface{}) {
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Fatal(args...)
}

func (l logger) Fatalln(args ...interface{}) {
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Fatalln(args...)
}

func (l logger) Fatalf(format string, args ...interface{}) {
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Fatalf(format, args...)
}

func (l logger) Panic(args ...interface{}) {
	defer func() {
		if r := recover(); r != nil {
			l.FlushTelemetry()
			panic(r)
		}
	}()
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Panic(args...)
}

func (l logger) Panicln(args ...interface{}) {
	defer func() {
		if r := recover(); r != nil {
			l.FlushTelemetry()
			panic(r)
		}
	}()
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Panicln(args...)
}

func (l logger) Panicf(format string, args ...interface{}) {
	defer func() {
		if r := recover(); r != nil {
			l.FlushTelemetry()
			panic(r)
		}
	}()
	l.source().Errorln(stackPrefix, string(debug.Stack()))
	l.source().Panicf(format, args...)
}

func (l logger) WithFields(fields Fields) Logger {
	return logger{
		l.source().WithFields(fields),
		l.loggerState,
	}
}

func (l logger) SetLevel(lvl Level) {
	l.entry.Logger.Level = logrus.Level(lvl)
}

func (l logger) IsLevelEnabled(level Level) bool {
	return l.entry.Logger.Level >= logrus.Level(level)
}

func (l logger) SetOutput(w io.Writer) {
	if l.GetTelemetryEnabled() {
		l.setOutput(l.loggerState.telemetry.wrapOutput(w))
	} else {
		l.setOutput(w)
	}
}

func (l logger) setOutput(w io.Writer) {
	l.entry.Logger.Out = w
}

func (l logger) getOutput() io.Writer {
	return l.entry.Logger.Out
}

func (l logger) SetJSONFormatter() {
	l.entry.Logger.Formatter = &logrus.JSONFormatter{TimestampFormat: "2006-01-02T15:04:05.000000Z07:00"}
}

func (l logger) source() *logrus.Entry {
	event := l.entry

	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "<???>"
		line = 1
	} else {
		// Add file name and number
		slash := strings.LastIndex(file, "/")
		file = file[slash+1:]
		event = event.WithFields(logrus.Fields{
			"file": file,
			"line": line,
		})

		// Add function name if possible
		if function := runtime.FuncForPC(pc); function != nil {
			event = event.WithField("function", function.Name())
		}
	}
	return event
}

func (l logger) AddHook(hook logrus.Hook) {
	l.entry.Logger.Hooks.Add(hook)
}

// Base returns the default Logger logging to
func Base() Logger {
	return baseLogger
}

// NewLogger returns a new Logger logging to out.
func NewLogger() Logger {
	l := logrus.New()
	out := logger{
		logrus.NewEntry(l),
		&loggerState{},
	}
	formatter := out.entry.Logger.Formatter
	tf, ok := formatter.(*logrus.TextFormatter)
	if ok {
		tf.TimestampFormat = "2006-01-02T15:04:05.000000 -0700"
	}
	return out
}

func (l logger) EnableTelemetry(cfg TelemetryConfig) (err error) {
	if l.loggerState.telemetry != nil || (!cfg.Enable && !cfg.SendToLog) {
		return nil
	}
	return EnableTelemetry(cfg, &l)
}

func (l logger) UpdateTelemetryURI(uri string) (err error) {
	err = l.loggerState.telemetry.hook.UpdateHookURI(uri)
	if err == nil {
		l.loggerState.telemetry.telemetryConfig.URI = uri
	}
	return
}

// GetTelemetryEnabled returns true if
// logging.config Enable, or SendToLog or config.json
// TelemetryToLog is true.
func (l logger) GetTelemetryEnabled() bool {
	return l.loggerState.telemetry != nil
}

func (l logger) GetTelemetrySession() string {
	if !l.GetTelemetryEnabled() {
		return ""
	}
	return l.loggerState.telemetry.telemetryConfig.SessionGUID
}

func (l logger) GetTelemetryHostName() string {
	if l.loggerState.telemetry == nil {
		return ""
	}
	return l.loggerState.telemetry.telemetryConfig.getHostName()
}

func (l logger) GetInstanceName() string {
	if !l.GetTelemetryEnabled() {
		return ""
	}
	return l.loggerState.telemetry.telemetryConfig.getInstanceName()
}

func (l logger) GetTelemetryURI() string {
	if !l.GetTelemetryEnabled() {
		return ""
	}
	return l.loggerState.telemetry.telemetryConfig.URI
}

// GetTelemetryUploadingEnabled returns true if telemetry logging is
// enabled for uploading messages.
// This is decided by Enable parameter in logging.config
func (l logger) GetTelemetryUploadingEnabled() bool {
	return l.GetTelemetryEnabled() &&
		l.loggerState.telemetry.telemetryConfig.Enable
}

func (l logger) Metrics(category telemetryspec.Category, metrics telemetryspec.MetricDetails, details interface{}) {
	if l.loggerState.telemetry != nil {
		l.loggerState.telemetry.logMetrics(l, category, metrics, details)
	}
}

func (l logger) Event(category telemetryspec.Category, identifier telemetryspec.Event) {
	l.EventWithDetails(category, identifier, nil)
}

func (l logger) EventWithDetails(category telemetryspec.Category, identifier telemetryspec.Event, details interface{}) {
	if l.loggerState.telemetry != nil {
		l.loggerState.telemetry.logEvent(l, category, identifier, details)
	}
}

func (l logger) StartOperation(category telemetryspec.Category, identifier telemetryspec.Operation) TelemetryOperation {
	if l.loggerState.telemetry != nil {
		return l.loggerState.telemetry.logStartOperation(l, category, identifier)
	}
	return TelemetryOperation{}
}

func (l logger) CloseTelemetry() {
	if l.loggerState.telemetry != nil {
		l.loggerState.telemetry.Close()
	}
}

func (l logger) FlushTelemetry() {
	if l.loggerState.telemetry != nil {
		l.loggerState.telemetry.Flush()
	}
}
