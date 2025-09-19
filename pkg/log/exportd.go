package log

import (
	"io"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var std = logrus.New()

func Apply(option *Option) {
	if option.Filename != "" {
		writer := &lumberjack.Logger{
			Filename:   option.Filename,
			MaxSize:    option.MaxSize,
			MaxAge:     option.MaxAge,
			MaxBackups: option.MaxBackup,
			Compress:   true,
		}
		if out, ok := std.Out.(io.Closer); ok && out != nil {
			defer func() {
				_ = out.Close()
			}()
		}
		std.SetOutput(writer)
		logrus.SetOutput(writer)
	}
	logrus.SetLevel(option.Level)
	std.SetLevel(option.Level)
}
func WithFields(fields Fields) Logger {
	return std.WithFields(fields)
}
func GetLogger(name string) Logger {
	return std.WithField("module", name)
}

func Trace(args ...interface{}) {
	std.Trace(args...)
}

func Debug(args ...interface{}) {
	std.Debug(args...)
}

func Print(args ...interface{}) {
	std.Print(args...)
}

func Info(args ...interface{}) {
	std.Info(args...)
}

func Warn(args ...interface{}) {
	std.Warn(args...)
}

func Error(args ...interface{}) {
	std.Error(args...)
}

func Panic(args ...interface{}) {
	std.Panic(args...)
}

func Fatal(args ...interface{}) {
	std.Fatal(args...)
}

func Tracef(format string, args ...interface{}) {
	std.Tracef(format, args...)
}

func Debugf(format string, args ...interface{}) {
	std.Debugf(format, args...)
}

func Printf(format string, args ...interface{}) {
	std.Printf(format, args...)
}

func Infof(format string, args ...interface{}) {
	std.Infof(format, args...)
}

func Warnf(format string, args ...interface{}) {
	std.Warnf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	std.Errorf(format, args...)
}

func Panicf(format string, args ...interface{}) {
	std.Panicf(format, args...)
}
