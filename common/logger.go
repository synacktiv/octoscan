package common

import (
	"io"
	"io/ioutil"
	"log"
)

type LogLevel byte

const (
	LogLevelQuiet LogLevel = iota
	LogLevelNormal
	LogLevelVerbose
	LogLevelDebug
)

var Log *Logger = NewLogger()
var logLevel LogLevel = LogLevelNormal

type Logger struct {
	writer   io.Writer
	_debug   *log.Logger
	_info    *log.Logger
	_verbose *log.Logger
	_error   *log.Logger
	_fatal   *log.Logger
}

func NewLogger() *Logger {
	l := Logger{
		writer: log.Writer(),
	}

	flags := log.Lmsgprefix | log.LstdFlags
	l._debug = log.New(ioutil.Discard, "[DEBUG] ", 0)
	l._info = log.New(l.writer, "[INFO] ", flags)
	l._verbose = log.New(ioutil.Discard, "[VERBOSE] ", flags)
	l._error = log.New(l.writer, "[ERROR] ", flags)
	l._fatal = log.New(l.writer, "[FATAL] ", flags)
	return &l
}

func (l *Logger) disableLogger(logger *log.Logger) {
	logger.SetOutput(ioutil.Discard)
	logger.SetFlags(0)
}

func (l *Logger) enableLogger(logger *log.Logger) {
	logger.SetOutput(l.writer)
	logger.SetFlags(log.Lmsgprefix | log.LstdFlags)
}

func (l *Logger) Debug(v ...interface{}) {
	l._debug.Println(v...)
}

func (l *Logger) Info(v ...interface{}) {
	l._info.Println(v...)
}

func (l *Logger) Verbose(v ...interface{}) {
	l._verbose.Println(v...)
}

func (l *Logger) Error(v ...interface{}) {
	l._error.Println(v...)
}

func (l *Logger) Fatal(v ...interface{}) {
	l._fatal.Fatal(v...)
}

func (l *Logger) SetLevel(level LogLevel) {
	switch level {
	case LogLevelQuiet:
		l.disableLogger(l._debug)
		l.disableLogger(l._verbose)
		l.disableLogger(l._info)
		l.disableLogger(l._error)
		l.disableLogger(l._fatal)
	case LogLevelNormal:
		l.disableLogger(l._debug)
		l.disableLogger(l._verbose)
		l.enableLogger(l._info)
		l.enableLogger(l._error)
		l.enableLogger(l._fatal)
	case LogLevelVerbose:
		l.disableLogger(l._debug)
		l.enableLogger(l._verbose)
		l.enableLogger(l._info)
		l.enableLogger(l._error)
		l.enableLogger(l._fatal)
	case LogLevelDebug:
		l.enableLogger(l._debug)
		l.enableLogger(l._verbose)
		l.enableLogger(l._info)
		l.enableLogger(l._error)
		l.enableLogger(l._fatal)
	}

	logLevel = level
}

func (l *Logger) GetLevel() LogLevel {
	return logLevel
}

func (l *Logger) DebugWriter() io.Writer {
	if logLevel < LogLevelDebug {
		return nil
	}
	return l.writer
}
