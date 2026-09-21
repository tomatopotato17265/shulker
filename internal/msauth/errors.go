package msauth

import "fmt"

type Step string

const (
	StepDeviceToken      Step = "device token"
	StepSisuAuthenticate Step = "sisu authenticate"
	StepSisuAuthorize    Step = "sisu authorize"
	StepXSTSAuthorize    Step = "xsts authorize"
)

type Error struct {
	Step   Step
	Status int
	Raw    string
	Err    error
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("login failed at %s", e.Step)
	if e.Status != 0 {
		msg += fmt.Sprintf(" (HTTP %d)", e.Status)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }
