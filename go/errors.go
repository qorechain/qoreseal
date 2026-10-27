// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"errors"
	"fmt"
)

// Stable error codes, identical in every QoreSeal implementation.
const (
	CodeInvalidArgument        = "INVALID_ARGUMENT"
	CodeInvalidKey             = "INVALID_KEY"
	CodeMalformedEnvelope      = "MALFORMED_ENVELOPE"
	CodeMalformedBatch         = "MALFORMED_BATCH"
	CodeUnsupportedVersion     = "UNSUPPORTED_VERSION"
	CodeUnsupportedAlgorithm   = "UNSUPPORTED_ALGORITHM"
	CodeNotARecipient          = "NOT_A_RECIPIENT"
	CodeDecryptionFailed       = "DECRYPTION_FAILED"
	CodeRecipientNeedsX25519   = "RECIPIENT_NEEDS_X25519"
	CodeCardInvalid            = "CARD_INVALID"
	CodeUnknownEpoch           = "UNKNOWN_EPOCH"
	CodeKemKeyNotRegistered    = "KEM_KEY_NOT_REGISTERED"
	CodeKemRegistryUnavailable = "KEM_REGISTRY_UNAVAILABLE"
	CodeNetworkUnavailable     = "NETWORK_UNAVAILABLE"
)

// Error is every error QoreSeal returns on purpose. Code is stable; Message is for people.
type Error struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string {
	return fmt.Sprintf("qoreseal: %s: %s", e.Code, e.Message)
}

// NewError builds an *Error.
func NewError(code, message string, details map[string]any) *Error {
	return &Error{Code: code, Message: message, Details: details}
}

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// IsCode reports whether err is (or wraps) an *Error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
