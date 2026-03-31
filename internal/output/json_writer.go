package output

import (
	"encoding/json"
	"io"
)

type JSONWriter struct {
	writer io.Writer
}

func NewJSONWriter(writer io.Writer) *JSONWriter {
	return &JSONWriter{writer: writer}
}

func (w *JSONWriter) Write(value any) error {
	encoder := json.NewEncoder(w.writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
