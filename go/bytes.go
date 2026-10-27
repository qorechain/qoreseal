// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
)

// ToHex returns lowercase hex.
func ToHex(b []byte) string { return hex.EncodeToString(b) }

// FromHex decodes hex.
func FromHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "invalid hex")
	}
	return b, nil
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u64(n uint64) []byte {
	return []byte{byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func readU64(b []byte) uint64 {
	var n uint64
	for _, x := range b[:8] {
		n = n<<8 | uint64(x)
	}
	return n
}

func equalBytes(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func isAllZero(b []byte) bool {
	var d byte
	for _, x := range b {
		d |= x
	}
	return d == 0
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}

// entropy is the randomness a seal consumes (spec section 9).
type entropy interface {
	take(n int) ([]byte, error)
	deterministic() bool
}

type systemEntropy struct{}

func (systemEntropy) take(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, errorf(CodeInvalidArgument, "system randomness failed: %v", err)
	}
	return b, nil
}

func (systemEntropy) deterministic() bool { return false }

// streamEntropy hands out a fixed byte string in order. For test vectors only.
type streamEntropy struct {
	b   []byte
	off int
}

func (s *streamEntropy) take(n int) ([]byte, error) {
	if s.off+n > len(s.b) {
		return nil, errorf(CodeInvalidArgument, "not enough test entropy")
	}
	out := clone(s.b[s.off : s.off+n])
	s.off += n
	return out, nil
}

func (s *streamEntropy) deterministic() bool { return true }

func (s *streamEntropy) done() error {
	if s.off != len(s.b) {
		return errorf(CodeInvalidArgument, "test entropy has unused bytes")
	}
	return nil
}
