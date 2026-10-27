// SPDX-License-Identifier: Apache-2.0

package qoreseal

import "regexp"

// Wire constants of QoreSeal v1 (spec/qoreseal-v1.md).
const (
	// AlgorithmMLKEM1024 is the algorithm id of ML-KEM-1024 in the chain's KEM key registry and in envelopes.
	AlgorithmMLKEM1024        = 2
	MLKEM1024PublicKeyLength  = 1568
	MLKEM1024SecretKeyLength  = 3168
	MLKEM1024CiphertextLength = 1568
	X25519KeyLength           = 32
	SeedLength                = 32

	EnvelopeVersion = 1
	// EnvelopeTextPrefix starts the text form of an envelope.
	EnvelopeTextPrefix = "qoreseal:"
	MaxRecipients      = 1024

	// KdfInfoPrefix is the prefix of the HKDF info of every key-encryption key.
	KdfInfoPrefix        = "qorechain-kem-v1|"
	HybridLabel          = "qorechain-qoreseal-hybrid-v1"
	HintLabel            = "qorechain-qoreseal-hint-v1"
	KeysLabelMLKEM       = "qorechain-qoreseal-keys-v1|ml-kem-1024"
	KeysLabelX25519      = "qorechain-qoreseal-keys-v1|x25519"
	MnemonicLabel        = "qorechain-qoreseal-mnemonic-v1|"
	BatchCommitmentLabel = "qorechain-qoreseal-batch-v1"

	modeHybridByte    = 0x01
	modeMlkemByte     = 0x02
	kdfHkdfSha256     = 0x01
	aeadAes256Gcm     = 0x01
	flagAnonymous     = 0x01
	fixedHeaderLength = 28
	saltLength        = 16
	hintLength        = 16
	nonceLength       = 12
	tagLength         = 16
	dataKeyLength     = 32
	wrappedKeyLength  = dataKeyLength + tagLength
)

var envelopeMagic = []byte("QSEL")

// Mode selects how each recipient's secret is formed.
type Mode string

const (
	// ModeHybrid (the default) uses ML-KEM-1024 plus X25519.
	ModeHybrid Mode = "hybrid"
	// ModeMlkem uses ML-KEM-1024 only and must be chosen explicitly.
	ModeMlkem Mode = "mlkem"
)

// EntryLength is the size of one recipient entry for a mode: 1664 bytes in hybrid mode, 1632 in mlkem mode.
func EntryLength(mode Mode) int {
	if mode == ModeMlkem {
		return 1632
	}
	return 1664
}

var (
	chainIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	purposeRe = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
)

func checkChainID(chainID string) error {
	if !chainIDRe.MatchString(chainID) {
		return errorf(CodeInvalidArgument, "invalid chain id %q", chainID)
	}
	return nil
}

func checkPurpose(purpose, what string) error {
	if !purposeRe.MatchString(purpose) {
		return errorf(CodeInvalidArgument, "invalid %s %q", what, purpose)
	}
	return nil
}

func normalizeMode(mode Mode) (Mode, byte, error) {
	switch mode {
	case "", ModeHybrid:
		return ModeHybrid, modeHybridByte, nil
	case ModeMlkem:
		return ModeMlkem, modeMlkemByte, nil
	}
	return "", 0, errorf(CodeInvalidArgument, "unknown mode %q", string(mode))
}
