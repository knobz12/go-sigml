package sigml

import "errors"

type SigMLRecord struct {
	Bn   string  `json:"bn,omitempty"`   //source device/system
	Bt   float64 `json:"bt,omitempty"`   // Basetime linux epoch
	Bver int     `json:"bver,omitempty"` // Version
	N    string  `json:"n,omitempty"`    //source service/signal

	X  string      `json:"x,omitempty"`  // Exception
	E  string      `json:"e,omitempty"`  // Error
	S  string      `json:"s,omitempty"`  // Signal/event
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

// Validate tests if a SigML message is well formated
func (msg SigMLMessage) Validate() error {
	if len(msg) == 0 {
		return errors.New("empty message")
	}

	for _, rec := range msg {
		if rec.X == "" && rec.E == "" && rec.S == "" {
			return errors.New("one of x, e or s must be valid")
		}
		if rec.X != "" && rec.E != "" && rec.S != "" {
			return errors.New("only one of x, e or s can be valid")
		}
		if rec.X != "" && (rec.E != "" || rec.S != "") {
			return errors.New("only one of x, e or s can be valid")
		}
		if (rec.X != "" || rec.E != "") && rec.S != "" {
			return errors.New("only one of x, e or s can be valid")
		}
	}
	return nil
}
