package receiver

import (
	"errors"
	"fmt"
	"time"
)

// Clock is the time now. Tests replace it.
type Clock func() time.Time

// SystemClock is the system clock.
func SystemClock() time.Time { return time.Now() }

// ErrorCode is one of the error codes of RFC 8935, section 2.4, and invalid_state of SSF 1.0,
// section 8.1.4.1. Decided by this package, not by the JWT library. The specification may add
// codes: do not switch over them exhaustively.
type ErrorCode string

const (
	// InvalidRequest: the SET is malformed or lacks a claim.
	InvalidRequest ErrorCode = "invalid_request"
	// InvalidKey: the SET is signed with a key the receiver does not accept.
	InvalidKey ErrorCode = "invalid_key"
	// InvalidIssuer: the SET was issued by another transmitter.
	InvalidIssuer ErrorCode = "invalid_issuer"
	// InvalidAudience: the SET is not addressed to this receiver.
	InvalidAudience ErrorCode = "invalid_audience"
	// InvalidState: the state of a verification event is not the expected one.
	InvalidState ErrorCode = "invalid_state"
)

// RejectedError says that a SET is invalid; the transmitter must not deliver it again. It
// carries the error code reported to the transmitter (RFC 8935, section 2.4).
type RejectedError struct {
	// Code is the RFC 8935 error code.
	Code ErrorCode
	// Description is for the error document and the log.
	Description string
}

func (e *RejectedError) Error() string { return fmt.Sprintf("%s (%s)", e.Description, e.Code) }

// Rejected is a rejection with an error code.
func Rejected(code ErrorCode, format string, args ...any) error {
	return &RejectedError{Code: code, Description: fmt.Sprintf(format, args...)}
}

// RejectionOf returns the rejection in err, nil if the SET was not rejected (the transmitter was
// unavailable, say).
func RejectionOf(err error) *RejectedError {
	var rejected *RejectedError
	if errors.As(err, &rejected) {
		return rejected
	}
	return nil
}

// TransmitterUnavailableError says that the transmitter's metadata or keys cannot be obtained.
// Unlike an invalid SET this is a temporary condition, the SET should be delivered again later.
type TransmitterUnavailableError struct {
	Message string
	Cause   error
}

func (e *TransmitterUnavailableError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap is the cause.
func (e *TransmitterUnavailableError) Unwrap() error { return e.Cause }

// Unavailable is an unavailability with a message and an optional cause.
func Unavailable(cause error, format string, args ...any) error {
	return &TransmitterUnavailableError{Message: fmt.Sprintf(format, args...), Cause: cause}
}

// IsTransmitterUnavailable reports whether err says the transmitter was unavailable.
func IsTransmitterUnavailable(err error) bool {
	var unavailable *TransmitterUnavailableError
	return errors.As(err, &unavailable)
}

// ErrInProgress says that another instance is handling the SET; leave it for redelivery.
var ErrInProgress = errors.New("the SET is being handled by another instance")

// HandlingError says that one or more handlers failed; the SET must be delivered again.
type HandlingError struct {
	// Failed is how many handlers returned an error.
	Failed int
	// First is the error of the first handler that failed.
	First error
}

func (e *HandlingError) Error() string {
	return fmt.Sprintf("%d handler(s) failed for the SET, the first with: %v", e.Failed, e.First)
}

// Unwrap is the first error.
func (e *HandlingError) Unwrap() error { return e.First }

// StoreError says that the dedup store failed.
type StoreError struct{ Cause error }

func (e *StoreError) Error() string { return "the dedup store failed: " + e.Cause.Error() }

// Unwrap is the cause.
func (e *StoreError) Unwrap() error { return e.Cause }
