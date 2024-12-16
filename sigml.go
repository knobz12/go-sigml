package sigml

import (
	"errors"
	"fmt"
)

type SigMLRecord struct {
	Bn   string  `json:"bn,omitempty"`   //source device/system
	Bt   float64 `json:"bt,omitempty"`   // Basetime linux epoch
	Bver int     `json:"bver,omitempty"` // Version
	N    string  `json:"n,omitempty"`    //source service/signal

	X  string      `json:"x,omitempty"`  // Exception
	E  string      `json:"e,omitempty"`  // Error
	S  string      `json:"s,omitempty"`  // Signal/event
	PR string      `json:"pr,omitempty"` // Policy request
	XC string      `json:"xc,omitempty"` // Execute command
	Se Severity    `json:"se,omitempty"` // Severity level
	D  string      `json:"d,omitempty"`  // Description
	P  interface{} `json:"p,omitempty"`  // Payload
}

type Severity uint8

const (
	None         Severity = 0
	Normal       Severity = 1
	Incident     Severity = 50
	Error        Severity = 100
	Critical     Severity = 200
	Catastrophic Severity = 255
)

type SigMLMessage []SigMLRecord

func (message SigMLMessage) NormalizeSigMLMessage() []map[string]interface{} {
	if len(message) == 0 {
		return nil
	}

	// Extract default `bn` and `bt` from the first record
	defaultBn := message[0].Bn
	defaultBt := message[0].Bt

	// Map severity levels to strings
	severityMap := map[Severity]string{
		None:         "None",
		Normal:       "Normal",
		Incident:     "Incident",
		Error:        "Error",
		Critical:     "Critical",
		Catastrophic: "Catastrophic",
	}

	// Normalize all records
	var normalized []map[string]interface{}
	for _, record := range message {
		// Use defaults if `bn` or `bt` are missing
		bn := record.Bn
		if bn == "" {
			bn = defaultBn
		}
		bt := record.Bt
		if bt == 0 {
			bt = defaultBt
		}

		// Create the normalized record
		normalizedRecord := map[string]interface{}{
			"bn":        bn,
			"bt":        fmt.Sprintf("%.3f", bt),
			"bver":      record.Bver,
			"n":         record.N,
			"exception": record.X,
			"error":     record.E,
			"signal":    record.S,
			"policy":    record.PR,
			"command":   record.XC,
			"severity":  severityMap[record.Se],
			"details":   record.D,
			"payload":   record.P,
		}

		normalized = append(normalized, normalizedRecord)
	}

	return normalized
}

// Validate tests if a SigML message is well formated
func (msg SigMLMessage) Validate() error {
	if len(msg) == 0 {
		return errors.New("empty message")
	}

	for _, rec := range msg {

		if rec.X == "" && rec.E == "" && rec.S == "" && rec.PR == "" && rec.XC == "" {
			return errors.New("one of x, e, s, pr or xc must be valid")
		}

		fields := []string{rec.X, rec.E, rec.S, rec.PR, rec.XC}
		count := 0
		for _, field := range fields {
			if field != "" {
				count++
			}
		}
		if count != 1 {
			return errors.New("only one of x, e, s, pr or xc can be valid")
		}

	}
	return nil
}
