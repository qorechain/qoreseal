// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"crypto/ecdh"
	"crypto/sha256"
	"io"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	bip39 "github.com/cosmos/go-bip39"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/text/unicode/norm"
)

// SealKeyPair is a recipient's keys: an ML-KEM-1024 key pair and an X25519
// key pair derived from one 32-byte seed. Keep Seed (or the mnemonic it came
// from) secret and backed up.
type SealKeyPair struct {
	Seed []byte
	// MlkemPublicKey is the ML-KEM-1024 encapsulation key (1568 bytes): the key registered on chain.
	MlkemPublicKey []byte
	// MlkemSecretKey is the ML-KEM-1024 decapsulation key (3168 bytes).
	MlkemSecretKey []byte
	// X25519PublicKey (32 bytes) is published in a recipient card.
	X25519PublicKey []byte
	X25519SecretKey []byte
}

// SealRecipient is what a sender needs. X25519PublicKey is required by the hybrid mode (nil when absent).
type SealRecipient struct {
	MlkemPublicKey  []byte
	X25519PublicKey []byte
}

func hkdfSha256(ikm, salt []byte, info string, n int) []byte {
	out := make([]byte, n)
	if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), out); err != nil {
		panic(err) // n is far below the HKDF-SHA-256 limit
	}
	return out
}

// SealKeysFromSeed derives both key pairs from a 32-byte seed (spec section 4).
func SealKeysFromSeed(seed []byte) (SealKeyPair, error) {
	if len(seed) != SeedLength {
		return SealKeyPair{}, errorf(CodeInvalidArgument, "seed must be %d bytes, got %d", SeedLength, len(seed))
	}
	mlkemSeed := hkdfSha256(seed, nil, KeysLabelMLKEM, 64)
	pk, sk := mlkem1024.NewKeyFromSeed(mlkemSeed)
	pkb, err := pk.MarshalBinary()
	if err != nil {
		return SealKeyPair{}, errorf(CodeInvalidKey, "ML-KEM-1024 key generation failed")
	}
	skb, err := sk.MarshalBinary()
	if err != nil {
		return SealKeyPair{}, errorf(CodeInvalidKey, "ML-KEM-1024 key generation failed")
	}
	xsk := hkdfSha256(seed, nil, KeysLabelX25519, 32)
	xpk, err := X25519PublicKey(xsk)
	if err != nil {
		return SealKeyPair{}, err
	}
	return SealKeyPair{Seed: clone(seed), MlkemPublicKey: pkb, MlkemSecretKey: skb, X25519PublicKey: xpk, X25519SecretKey: xsk}, nil
}

// GenerateSealKeys returns key pairs from a fresh random seed.
func GenerateSealKeys() (SealKeyPair, error) {
	seed, err := systemEntropy{}.take(SeedLength)
	if err != nil {
		return SealKeyPair{}, err
	}
	return SealKeysFromSeed(seed)
}

// MnemonicOptions select the seed derived from a mnemonic.
type MnemonicOptions struct {
	// Passphrase is the optional BIP-39 passphrase.
	Passphrase string
	// Index is 0 to 2^31-1; move to the next index to rotate keys.
	Index uint32
}

// SealSeedFromMnemonic derives the 32-byte seed for an index from a BIP-39 mnemonic (spec section 4).
func SealSeedFromMnemonic(mnemonic string, opts MnemonicOptions) ([]byte, error) {
	if opts.Index > 0x7fffffff {
		return nil, errorf(CodeInvalidArgument, "index must be from 0 to 2^31-1, got %d", opts.Index)
	}
	// BIP-39 normalizes both the mnemonic and the passphrase to NFKD.
	m := strings.Join(strings.Fields(norm.NFKD.String(mnemonic)), " ")
	if !bip39.IsMnemonicValid(m) {
		return nil, errorf(CodeInvalidArgument, "invalid BIP-39 mnemonic")
	}
	bipSeed, err := bip39.NewSeedWithErrorChecking(m, norm.NFKD.String(opts.Passphrase))
	if err != nil {
		return nil, errorf(CodeInvalidArgument, "invalid BIP-39 mnemonic")
	}
	return hkdfSha256(bipSeed, nil, MnemonicLabel+strconv.FormatUint(uint64(opts.Index), 10), SeedLength), nil
}

// DeriveSealKeys derives key pairs from a BIP-39 mnemonic.
func DeriveSealKeys(mnemonic string, opts MnemonicOptions) (SealKeyPair, error) {
	seed, err := SealSeedFromMnemonic(mnemonic, opts)
	if err != nil {
		return SealKeyPair{}, err
	}
	return SealKeysFromSeed(seed)
}

// RecipientOf returns the public half of a key pair, as a recipient.
func RecipientOf(k SealKeyPair) SealRecipient {
	return SealRecipient{MlkemPublicKey: clone(k.MlkemPublicKey), X25519PublicKey: clone(k.X25519PublicKey)}
}

// ValidateMlkemPublicKey applies the checks the chain applies to a registered
// key: 1568 bytes, every 12-bit coefficient of t_hat below 3329 (FIPS 203
// modulus check), t_hat not all zero. It returns INVALID_KEY.
func ValidateMlkemPublicKey(pub []byte) error {
	if len(pub) != MLKEM1024PublicKeyLength {
		return errorf(CodeInvalidKey, "ML-KEM-1024 public key must be %d bytes, got %d", MLKEM1024PublicKeyLength, len(pub))
	}
	nonZero := false
	for i := 0; i < 1536; i += 3 {
		c0 := uint16(pub[i]) | uint16(pub[i+1]&0x0f)<<8
		c1 := uint16(pub[i+1]>>4) | uint16(pub[i+2])<<4
		if c0 >= 3329 || c1 >= 3329 {
			return errorf(CodeInvalidKey, "the ML-KEM-1024 public key fails the FIPS 203 modulus check")
		}
		if c0 != 0 || c1 != 0 {
			nonZero = true
		}
	}
	if !nonZero {
		return errorf(CodeInvalidKey, "the ML-KEM-1024 public key is degenerate (t_hat is zero)")
	}
	return nil
}

// ValidateX25519PublicKey checks the length and refuses the zero key.
func ValidateX25519PublicKey(pub []byte) error {
	if len(pub) != X25519KeyLength {
		return errorf(CodeInvalidKey, "X25519 public key must be 32 bytes, got %d", len(pub))
	}
	if isAllZero(pub) {
		return errorf(CodeInvalidKey, "the X25519 public key is zero")
	}
	return nil
}

func checkKeyPair(k SealKeyPair) error {
	if len(k.MlkemSecretKey) != MLKEM1024SecretKeyLength {
		return errorf(CodeInvalidKey, "ML-KEM-1024 secret key must be %d bytes", MLKEM1024SecretKeyLength)
	}
	if len(k.MlkemPublicKey) != MLKEM1024PublicKeyLength {
		return errorf(CodeInvalidKey, "ML-KEM-1024 public key must be %d bytes", MLKEM1024PublicKeyLength)
	}
	if len(k.X25519SecretKey) != X25519KeyLength {
		return errorf(CodeInvalidKey, "X25519 secret key must be 32 bytes")
	}
	return nil
}

// X25519PublicKey returns X25519(secretKey, 9).
func X25519PublicKey(secretKey []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(secretKey)
	if err != nil {
		return nil, errorf(CodeInvalidKey, "X25519 secret key must be 32 bytes")
	}
	return sk.PublicKey().Bytes(), nil
}
