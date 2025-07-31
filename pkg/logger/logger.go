package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logDir      = "/var/log/alpamon"
	logFileName = "alpamon.log"
	recordURL   = "/api/history/logs/"
)

type LogRecord struct {
	Date    string `json:"date"`
	Level   int    `json:"level"`
	Program string `json:"program"`
	Path    string `json:"path"`
	Lineno  int    `json:"lineno"`
	PID     int    `json:"pid"`
	Msg     string `json:"msg"`
}

type ZerologEntry struct {
	Level   string `json:"level"`
	Time    string `json:"time"`
	Caller  string `json:"caller"`
	Message string `json:"message"`
}

type logRecordWriter struct{}

// logRecordFileHandlers defines log level thresholds for specific files.
// Only files listed here will have their logs sent to the remote server.
// Logs from files not listed will be ignored entirely.
// Logs below the specified level for a listed file will also be ignored.
var logRecordFileHandlers = map[string]int{
	"command.go": 30,
	"commit.go":  20,
	"pty.go":     30,
	"shell.go":   30,
	"server.go":  40, // logger/server.go
}

func InitLogger() *lumberjack.Logger {
	fileName := fmt.Sprintf("%s/%s", logDir, logFileName)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		fileName = logFileName
	}

	// Set up lumberjack logger for log rotation
	logRotate := &lumberjack.Logger{
		Filename:   fileName,
		MaxSize:    50, // Max size in MB before rotation
		MaxBackups: 5,  // Max number of backup files
		MaxAge:     30, // Max age in days
		Compress:   true,
	}

	recordWriter := &logRecordWriter{}

	var output io.Writer
	if version.Version == "dev" {
		// In development, log to console with caller info
		output = zerolog.MultiLevelWriter(PrettyWriter(os.Stderr, true), recordWriter)
	} else {
		// In production, log to file without caller info in PrettyWriter
		output = zerolog.MultiLevelWriter(PrettyWriter(logRotate, false), recordWriter)
	}
	// Always include .Caller() so entry.Caller is set for logRecordWriter
	log.Logger = zerolog.New(output).With().Timestamp().Caller().Logger()

	return logRotate
}

// PrettyWriter returns a zerolog.ConsoleWriter with or without caller info
func PrettyWriter(out io.Writer, showCaller bool) zerolog.ConsoleWriter {
	cw := zerolog.ConsoleWriter{
		Out:          out,
		NoColor:      true,
		TimeFormat:   time.RFC3339,
		TimeLocation: time.Local,
		FormatLevel: func(i interface{}) string {
			return "[" + strings.ToUpper(fmt.Sprint(i)) + "]"
		},
		FormatMessage: func(i interface{}) string {
			return fmt.Sprint(i)
		},
		FormatFieldName: func(i interface{}) string {
			return "(" + fmt.Sprint(i) + ")"
		},
		FormatFieldValue: func(i interface{}) string {
			return fmt.Sprint(i)
		},
	}
	if showCaller {
		cw.FormatCaller = func(i interface{}) string {
			if i == nil || i == "" {
				return ""
			}
			callerStr := fmt.Sprint(i)
			if idx := strings.Index(callerStr, "/alpamon/"); idx != -1 {
				callerStr = callerStr[idx+len("/alpamon/"):]
			}
			return fmt.Sprintf("(%s)", callerStr)
		}
	} else {
		cw.FormatCaller = func(i interface{}) string { return "" }
	}
	return cw
}

// Note: Always return nil error to avoid zerolog internal error logs
func (w *logRecordWriter) Write(p []byte) (n int, err error) {
	var entry ZerologEntry
	err = json.Unmarshal(p, &entry)
	if err != nil {
		return 0, nil
	}

	n = len(p)
	if entry.Caller == "" {
		return n, nil
	}

	callerFileName, lineNo := ParseCaller(entry.Caller)

	levelThreshold, exists := logRecordFileHandlers[callerFileName]
	if !exists {
		return n, nil
	}

	level := ConvertLevelToNumber(entry.Level)
	if level < levelThreshold {
		return n, nil
	}

	record := LogRecord{
		Date:    entry.Time,
		Level:   level,
		Program: "alpamon",
		Path:    entry.Caller,
		Lineno:  lineNo,
		PID:     os.Getpid(),
		Msg:     entry.Message,
	}

	go func() {
		if scheduler.Rqueue == nil {
			return
		}
		scheduler.Rqueue.Post(recordURL, record, 90, time.Time{})
	}()

	return n, nil
}

// alpacon-server uses Python's logging package, which has different log levels from zerolog.
// This function maps zerolog log levels to Python logging levels.
func ConvertLevelToNumber(level string) int {
	switch level {
	case "fatal":
		return 50 // CRITICAL, FATAL
	case "error":
		return 40 // ERROR
	case "warn", "warning":
		return 30 // WARNING
	case "info":
		return 20 // INFO
	case "debug":
		return 10 // DEBUG
	default:
		return 0 // NOT SET
	}
}

func ParseCaller(caller string) (fileName string, lineno int) {
	parts := strings.Split(caller, ":")
	fileName = ""
	lineno = 0
	if len(parts) > 0 {
		fileName = filepath.Base(parts[0])
	}
	if len(parts) > 1 {
		if n, err := strconv.Atoi(parts[1]); err == nil {
			lineno = n
		}
	}
	return fileName, lineno
}
