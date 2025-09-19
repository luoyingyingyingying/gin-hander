package log

import "github.com/sirupsen/logrus"

type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Printf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Panicf(format string, args ...interface{})
	Tracef(format string, args ...interface{})

	Debug(args ...interface{})
	Info(args ...interface{})
	Print(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
	Panic(args ...interface{})
	Trace(args ...interface{})

	Debugln(args ...interface{})
	Infoln(args ...interface{})
	Println(args ...interface{})
	Warnln(args ...interface{})
	Errorln(args ...interface{})
	Fatalln(args ...interface{})
	Panicln(args ...interface{})
	Traceln(args ...interface{})
}
type Fields = logrus.Fields
type Level = logrus.Level

const (
	LevelPanic Level = logrus.PanicLevel
	LevelFatal Level = logrus.FatalLevel
	LevelError Level = logrus.ErrorLevel
	LevelWarn  Level = logrus.WarnLevel
	LevelInfo  Level = logrus.InfoLevel
	LevelDebug Level = logrus.DebugLevel
	LevelTrace Level = logrus.TraceLevel
)

type Option struct {
	Filename  string
	Level     Level
	MaxSize   int
	MaxAge    int
	MaxBackup int
}
