package domain

import (
	"errors"
	"fmt"
)

const (
	CodeProjectNotSupported = "PROJECT_NOT_SUPPORTED"
	CodeFileNotFound        = "FILE_NOT_FOUND"
	CodeInvalidJSON         = "INVALID_JSON"
	CodeLockfileNotFound    = "LOCKFILE_NOT_FOUND"
	CodeReadError           = "READ_ERROR"
	CodeInternalError       = "INTERNAL_ERROR"
	CodeUnsupportedFormat   = "UNSUPPORTED_FORMAT"
)

type CLIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type AppError struct {
	Code    string
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

func (e *AppError) ToCLIError() *CLIError {
	return &CLIError{Code: e.Code, Message: e.Message}
}

func NewAppError(code, message string, err error) *AppError {
	return &AppError{Code: code, Message: message, Err: err}
}

func ToCLIError(err error) *CLIError {
	if err == nil {
		return nil
	}

	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.ToCLIError()
	}

	return &CLIError{Code: CodeInternalError, Message: err.Error()}
}
