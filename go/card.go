// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"crypto/sha3"
	"errors"
	"regexp"
	"strings"
	"time"

	qoresign "github.com/qorechain/qoresign/go"
)

// Recipient card constants (spec section 7).
const (
	RecipientCardVersion = 1
	RecipientCardTitle   = "QoreSeal recipient card v1"
)

// RecipientCardFields are the signed fields of a recipient card.
type RecipientCardFields struct {
	ChainID string `json:"chainId"`
	// Address is the qor1 account the card belongs to.
	Address string `json:"address"`
	// MlkemKeySha3 is the hex SHA3-256 of the ML-KEM-1024 key registered on chain.
	MlkemKeySha3 string `json:"mlkemKeySha3"`
	// X25519PublicKey is the hex X25519 public key.
	X25519PublicKey string `json:"x25519PublicKey"`
	// IssuedAt is YYYY-MM-DDTHH:MM:SSZ.
	IssuedAt string `json:"issuedAt"`
}

// RecipientCard is a signed recipient card, in the JSON shape shared by every implementation.
type RecipientCard struct {
	Version int `json:"version"`
	RecipientCardFields
	// Signature is a QoreSign message signature over RecipientCardSignBytes.
	Signature qoresign.MessageSignature `json:"signature"`
}

var (
	issuedAtRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	hex32Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func cardInvalid(format string, args ...any) error {
	return errorf(CodeCardInvalid, format, args...)
}

func checkCardFields(f RecipientCardFields) error {
	if checkChainID(f.ChainID) != nil {
		return cardInvalid("invalid chain id")
	}
	addr, err := qoresign.ParseAddress(f.Address)
	if err != nil {
		return cardInvalid("invalid address")
	}
	if addr.Bech32 != f.Address {
		return cardInvalid("the address must be the qor1 form")
	}
	if !hex32Re.MatchString(f.MlkemKeySha3) {
		return cardInvalid("mlkemKeySha3 must be 64 lowercase hex characters")
	}
	if !hex32Re.MatchString(f.X25519PublicKey) {
		return cardInvalid("x25519PublicKey must be 64 lowercase hex characters")
	}
	if !issuedAtRe.MatchString(f.IssuedAt) {
		return cardInvalid("issuedAt must be YYYY-MM-DDTHH:MM:SSZ")
	}
	return nil
}

// RecipientCardText is the exact text the account signs (spec section 7).
func RecipientCardText(f RecipientCardFields) (string, error) {
	if err := checkCardFields(f); err != nil {
		return "", err
	}
	return strings.Join([]string{
		RecipientCardTitle,
		"Chain ID: " + f.ChainID,
		"Address: " + f.Address,
		"ML-KEM-1024 key SHA3-256: " + f.MlkemKeySha3,
		"X25519 key: " + f.X25519PublicKey,
		"Issued at: " + f.IssuedAt,
	}, "\n"), nil
}

// RecipientCardSignBytes is the UTF-8 of RecipientCardText.
func RecipientCardSignBytes(f RecipientCardFields) ([]byte, error) {
	s, err := RecipientCardText(f)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// FormatIssuedAt formats a time as a card's issuedAt (UTC, seconds).
func FormatIssuedAt(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// RecipientCardFieldsFor returns the card fields for a key pair; sign them
// with SignRecipientCard or a wallet's signArbitrary. An empty issuedAt uses the current time.
func RecipientCardFieldsFor(chainID, address string, keys SealKeyPair, issuedAt string) (RecipientCardFields, error) {
	if err := ValidateMlkemPublicKey(keys.MlkemPublicKey); err != nil {
		return RecipientCardFields{}, err
	}
	if err := ValidateX25519PublicKey(keys.X25519PublicKey); err != nil {
		return RecipientCardFields{}, err
	}
	if issuedAt == "" {
		issuedAt = FormatIssuedAt(time.Now())
	}
	h := sha3.Sum256(keys.MlkemPublicKey)
	f := RecipientCardFields{
		ChainID:         chainID,
		Address:         address,
		MlkemKeySha3:    ToHex(h[:]),
		X25519PublicKey: ToHex(keys.X25519PublicKey),
		IssuedAt:        issuedAt,
	}
	if err := checkCardFields(f); err != nil {
		return RecipientCardFields{}, err
	}
	return f, nil
}

// SignRecipientCardArgs are the inputs of SignRecipientCard.
type SignRecipientCardArgs struct {
	ChainID      string
	Address      string
	Keys         SealKeyPair
	ClassicalKey qoresign.ClassicalKey
	PqKey        qoresign.PqKeyPair
	// IssuedAt is YYYY-MM-DDTHH:MM:SSZ; empty uses the current time.
	IssuedAt string
}

// SignRecipientCard signs a card with the account's classical and ML-DSA-87 keys (QoreSign SignMessage).
func SignRecipientCard(args SignRecipientCardArgs) (RecipientCard, error) {
	f, err := RecipientCardFieldsFor(args.ChainID, args.Address, args.Keys, args.IssuedAt)
	if err != nil {
		return RecipientCard{}, err
	}
	data, err := RecipientCardSignBytes(f)
	if err != nil {
		return RecipientCard{}, err
	}
	pq := args.PqKey
	sig, err := qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: f.ChainID, Signer: f.Address, Data: data, ClassicalKey: args.ClassicalKey, PqKey: &pq,
	})
	if err != nil {
		return RecipientCard{}, err
	}
	return RecipientCard{Version: RecipientCardVersion, RecipientCardFields: f, Signature: sig}, nil
}

// AssembleRecipientCard attaches a signature produced elsewhere (for example by a wallet) to card fields.
func AssembleRecipientCard(f RecipientCardFields, sig qoresign.MessageSignature) (RecipientCard, error) {
	if err := checkCardFields(f); err != nil {
		return RecipientCard{}, err
	}
	return RecipientCard{Version: RecipientCardVersion, RecipientCardFields: f, Signature: sig}, nil
}

// VerifyRecipientCardArgs are the inputs of VerifyRecipientCard.
type VerifyRecipientCardArgs struct {
	Card    RecipientCard
	ChainID string
	// Address is the expected account; empty accepts the card's own.
	Address string
	// PqPublicKey is the ML-DSA-87 key registered for the account (/qorechain/pqc/v1/account/{address}).
	PqPublicKey []byte
	// MlkemPublicKey is the ML-KEM-1024 key registered for the account (/qorechain/pqc/v1/kem/{address}).
	MlkemPublicKey []byte
}

// VerifyRecipientCard checks a card against the keys the account has on
// chain and returns the hybrid recipient. Failures are CARD_INVALID.
func VerifyRecipientCard(args VerifyRecipientCardArgs) (SealRecipient, error) {
	c := args.Card
	if c.Version != RecipientCardVersion {
		return SealRecipient{}, cardInvalid("unsupported card version")
	}
	if err := checkCardFields(c.RecipientCardFields); err != nil {
		return SealRecipient{}, err
	}
	if c.ChainID != args.ChainID {
		return SealRecipient{}, cardInvalid("the card is for chain %s, not %s", c.ChainID, args.ChainID)
	}
	if args.Address != "" && c.Address != args.Address {
		return SealRecipient{}, cardInvalid("the card is for %s, not %s", c.Address, args.Address)
	}
	if ValidateMlkemPublicKey(args.MlkemPublicKey) != nil {
		return SealRecipient{}, cardInvalid("the registered ML-KEM-1024 key is not valid")
	}
	h := sha3.Sum256(args.MlkemPublicKey)
	want, _ := FromHex(c.MlkemKeySha3)
	if !equalBytes(h[:], want) {
		return SealRecipient{}, cardInvalid("the card names a different ML-KEM-1024 key than the registered one")
	}
	x, _ := FromHex(c.X25519PublicKey)
	if ValidateX25519PublicKey(x) != nil {
		return SealRecipient{}, cardInvalid("the card's X25519 key is not valid")
	}
	data, err := RecipientCardSignBytes(c.RecipientCardFields)
	if err != nil {
		return SealRecipient{}, err
	}
	requirePq := true
	if err := qoresign.VerifyMessage(qoresign.VerifyMessageOptions{
		ChainID: c.ChainID, Signer: c.Address, Data: data, Signature: c.Signature,
		PqPublicKey: args.PqPublicKey, RequirePq: &requirePq,
	}); err != nil {
		var qe *qoresign.Error
		if errors.As(err, &qe) {
			return SealRecipient{}, cardInvalid("the card signature does not verify (%s)", qe.Code)
		}
		return SealRecipient{}, cardInvalid("the card signature does not verify")
	}
	return SealRecipient{MlkemPublicKey: clone(args.MlkemPublicKey), X25519PublicKey: x}, nil
}
