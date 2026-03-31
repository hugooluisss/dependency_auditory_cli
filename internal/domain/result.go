package domain

type EnvelopeResponse struct {
	OK    bool      `json:"ok"`
	Data  any       `json:"data"`
	Error *CLIError `json:"error"`
}
