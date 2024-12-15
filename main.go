package main

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
	PR string	   `json:"pr,omitempty"`  // Policy request
	XC string	   `json:"xc,omitempty"`  // Execute command
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
func Validate(msg SigMLMessage)  error {
	if len(msg) == 0 {
		return errors.New("empty message")
	}

	for _, rec := range msg {

		if rec.X == "" && rec.E == "" && rec.S == "" && rec.PR == "" && rec.XC == ""{
			return errors.New("one of x, e, s, pr or xc must be valid")
		}

		fields := []string{rec.X, rec.E, rec.S, rec.PR, rec.XC}
		count := 0
		for _, field := range fields {
			if field != "" {
			count++
			}
		}
		if count != 1{
			return errors.New("only one of x, e, s, pr or xc can be valid")
		}
	
	}
	return nil
}

func main(){

p := []SigMLRecord{{
	Bn: "urn:dev:mac:00170d451f62:",
	Bt: 176627612.2,
	N:  "Name",
	PR: "test",
	XC: "test",
}}
//jsonBytes, _ := json.Marshal(p)


fmt.Print(Validate(p))
}