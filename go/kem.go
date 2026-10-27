// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"crypto/ecdh"
	"crypto/sha3"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	pqc "github.com/qorechain/qorechain-pqc/go"
)

// KdfInfo returns "qorechain-kem-v1|" + chainID + "|" + purpose, the HKDF info of every key-encryption key.
func KdfInfo(chainID, purpose string) (string, error) {
	if err := checkChainID(chainID); err != nil {
		return "", err
	}
	if err := checkPurpose(purpose, "purpose"); err != nil {
		return "", err
	}
	return KdfInfoPrefix + chainID + "|" + purpose, nil
}

// DeriveKey is HKDF-SHA-256 of a 32-byte shared secret into a 32-byte key
// bound to the chain and purpose. salt may be nil (empty).
func DeriveKey(shared []byte, chainID, purpose string, salt []byte) ([]byte, error) {
	if len(shared) != 32 {
		return nil, errorf(CodeInvalidArgument, "shared secret must be 32 bytes")
	}
	info, err := KdfInfo(chainID, purpose)
	if err != nil {
		return nil, err
	}
	return hkdfSha256(shared, salt, info, 32), nil
}

// MlkemEncapsulate encapsulates to a validated ML-KEM-1024 key, returning (ciphertext, shared secret).
func MlkemEncapsulate(publicKey []byte) (ct, ss []byte, err error) {
	if err := ValidateMlkemPublicKey(publicKey); err != nil {
		return nil, nil, err
	}
	ct, ss, err = pqc.MLKEM1024.Encapsulate(publicKey)
	if err != nil {
		return nil, nil, errorf(CodeInvalidKey, "ML-KEM-1024 encapsulation failed")
	}
	return ct, ss, nil
}

// mlkemEncapsulateDerand is ML-KEM.Encaps_internal with explicit m. For test vectors only.
func mlkemEncapsulateDerand(publicKey, m []byte) (ct, ss []byte, err error) {
	if err := ValidateMlkemPublicKey(publicKey); err != nil {
		return nil, nil, err
	}
	if len(m) != 32 {
		return nil, nil, errorf(CodeInvalidArgument, "encapsulation randomness must be 32 bytes")
	}
	s := mlkem1024.Scheme()
	pk, err := s.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, errorf(CodeInvalidKey, "invalid ML-KEM-1024 public key")
	}
	ct, ss, err = s.EncapsulateDeterministically(pk, m)
	if err != nil {
		return nil, nil, errorf(CodeInvalidKey, "ML-KEM-1024 encapsulation failed")
	}
	return ct, ss, nil
}

// MlkemDecapsulate recovers the shared secret of an ML-KEM-1024 ciphertext.
func MlkemDecapsulate(secretKey, ciphertext []byte) ([]byte, error) {
	if len(secretKey) != MLKEM1024SecretKeyLength {
		return nil, errorf(CodeInvalidKey, "ML-KEM-1024 secret key must be %d bytes", MLKEM1024SecretKeyLength)
	}
	if len(ciphertext) != MLKEM1024CiphertextLength {
		return nil, errorf(CodeInvalidArgument, "ML-KEM-1024 ciphertext must be %d bytes", MLKEM1024CiphertextLength)
	}
	ss, err := pqc.MLKEM1024.Decapsulate(secretKey, ciphertext)
	if err != nil {
		return nil, errorf(CodeInvalidKey, "ML-KEM-1024 decapsulation failed")
	}
	return ss, nil
}

// X25519Agree is X25519(secretKey, publicKey); an all-zero result (low-order public key) gives INVALID_KEY.
func X25519Agree(secretKey, publicKey []byte) ([]byte, error) {
	sk, err := ecdh.X25519().NewPrivateKey(secretKey)
	if err != nil {
		return nil, errorf(CodeInvalidKey, "X25519 secret key must be 32 bytes")
	}
	pk, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, errorf(CodeInvalidKey, "X25519 public key must be 32 bytes")
	}
	out, err := sk.ECDH(pk)
	if err != nil || isAllZero(out) {
		return nil, errorf(CodeInvalidKey, "X25519 agreement gave the zero point (low-order public key)")
	}
	return out, nil
}

// HybridSharedSecret is SHA3-256("qorechain-qoreseal-hybrid-v1" || ssMlkem || ssX25519 || ctX25519 || pkX25519).
func HybridSharedSecret(mlkemSharedSecret, x25519SharedSecret, x25519Ciphertext, x25519PublicKey []byte) ([]byte, error) {
	for _, b := range [][]byte{mlkemSharedSecret, x25519SharedSecret, x25519Ciphertext, x25519PublicKey} {
		if len(b) != 32 {
			return nil, errorf(CodeInvalidArgument, "hybrid combiner inputs must be 32 bytes each")
		}
	}
	h := sha3.Sum256(concat([]byte(HybridLabel), mlkemSharedSecret, x25519SharedSecret, x25519Ciphertext, x25519PublicKey))
	return h[:], nil
}

// RecipientHint is SHA3-256("qorechain-qoreseal-hint-v1" || salt || mlkemPublicKey)[0..16].
func RecipientHint(salt, mlkemPublicKey []byte) []byte {
	h := sha3.Sum256(concat([]byte(HintLabel), salt, mlkemPublicKey))
	return clone(h[:hintLength])
}
