// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
)

// SealArgs are the inputs of Seal.
type SealArgs struct {
	ChainID string
	// Purpose names what the data is for in your application, e.g. "chat" or "invoice" (spec section 3).
	Purpose    string
	Recipients []SealRecipient
	Plaintext  []byte
	// AAD is authenticated but not encrypted; the recipient must pass the same bytes.
	AAD []byte
	// Mode defaults to ModeHybrid. ModeMlkem must be chosen explicitly.
	Mode Mode
	// Anonymous zeroes the hints: recipients try every entry.
	Anonymous bool
}

// OpenArgs are the inputs of Open.
type OpenArgs struct {
	ChainID  string
	Purpose  string
	Envelope []byte
	Keys     SealKeyPair
	AAD      []byte
}

// EnvelopeEntry is one recipient entry of an envelope.
type EnvelopeEntry struct {
	Hint            []byte
	MlkemCiphertext []byte
	// X25519Ciphertext is the X25519 ephemeral public key (hybrid mode only, nil otherwise).
	X25519Ciphertext []byte
	WrappedKey       []byte
}

// ParsedEnvelope is the structure of an envelope, read without decrypting it.
type ParsedEnvelope struct {
	Version   int
	Mode      Mode
	Anonymous bool
	Salt      []byte
	Entries   []EnvelopeEntry
	Nonce     []byte
	// Ciphertext is the payload ciphertext with its tag.
	Ciphertext []byte
	// Header is everything before the ciphertext; the payload's AAD starts with it.
	Header []byte
}

// EnvelopeSize is the size in bytes of an envelope: 56 + recipients * EntryLength(mode) + plaintextLength.
func EnvelopeSize(mode Mode, recipients, plaintextLength int) int {
	return fixedHeaderLength + recipients*EntryLength(mode) + nonceLength + plaintextLength + tagLength
}

func gcmFor(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // keys are always 32 bytes here
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

func fixedHeader(mb byte, anonymous bool, salt []byte, n int) []byte {
	var flags byte
	if anonymous {
		flags = flagAnonymous
	}
	return concat(envelopeMagic, []byte{EnvelopeVersion, mb, AlgorithmMLKEM1024, kdfHkdfSha256, aeadAes256Gcm, flags}, salt, []byte{byte(n >> 8), byte(n)})
}

var zeroNonce = make([]byte, nonceLength)

func sealWith(args SealArgs, ent entropy) ([]byte, error) {
	if err := checkChainID(args.ChainID); err != nil {
		return nil, err
	}
	if err := checkPurpose(args.Purpose, "purpose"); err != nil {
		return nil, err
	}
	mode, mb, err := normalizeMode(args.Mode)
	if err != nil {
		return nil, err
	}
	n := len(args.Recipients)
	if n == 0 || n > MaxRecipients {
		return nil, errorf(CodeInvalidArgument, "between 1 and %d recipients are required", MaxRecipients)
	}
	for _, r := range args.Recipients {
		if err := ValidateMlkemPublicKey(r.MlkemPublicKey); err != nil {
			return nil, err
		}
		if mode == ModeHybrid {
			if r.X25519PublicKey == nil {
				return nil, errorf(CodeRecipientNeedsX25519,
					"hybrid mode needs each recipient's X25519 key (from a recipient card); choose ModeMlkem explicitly to use the on-chain key alone")
			}
			if err := ValidateX25519PublicKey(r.X25519PublicKey); err != nil {
				return nil, err
			}
		}
	}
	salt, err := ent.take(saltLength)
	if err != nil {
		return nil, err
	}
	dek, err := ent.take(dataKeyLength)
	if err != nil {
		return nil, err
	}
	fixed := fixedHeader(mb, args.Anonymous, salt, n)
	header := clone(fixed)
	for _, r := range args.Recipients {
		hint := make([]byte, hintLength)
		if !args.Anonymous {
			hint = RecipientHint(salt, r.MlkemPublicKey)
		}
		var ctK, ssK []byte
		if ent.deterministic() {
			m, err := ent.take(32)
			if err != nil {
				return nil, err
			}
			ctK, ssK, err = mlkemEncapsulateDerand(r.MlkemPublicKey, m)
			if err != nil {
				return nil, err
			}
		} else if ctK, ssK, err = MlkemEncapsulate(r.MlkemPublicKey); err != nil {
			return nil, err
		}
		shared := ssK
		var ctX []byte
		if mode == ModeHybrid {
			eSk, err := ent.take(32)
			if err != nil {
				return nil, err
			}
			if ctX, err = X25519PublicKey(eSk); err != nil {
				return nil, err
			}
			ssX, err := X25519Agree(eSk, r.X25519PublicKey)
			if err != nil {
				return nil, err
			}
			if shared, err = HybridSharedSecret(ssK, ssX, ctX, r.X25519PublicKey); err != nil {
				return nil, err
			}
		}
		kek, err := DeriveKey(shared, args.ChainID, args.Purpose, salt)
		if err != nil {
			return nil, err
		}
		wrapped := gcmFor(kek).Seal(nil, zeroNonce, dek, concat(fixed, hint, ctK, ctX))
		header = concat(header, hint, ctK, ctX, wrapped)
	}
	nonce, err := ent.take(nonceLength)
	if err != nil {
		return nil, err
	}
	header = concat(header, nonce)
	ct := gcmFor(dek).Seal(nil, nonce, args.Plaintext, concat(header, args.AAD))
	return concat(header, ct), nil
}

// Seal encrypts Plaintext to one or more recipients and returns the binary envelope.
func Seal(args SealArgs) ([]byte, error) {
	return sealWith(args, systemEntropy{})
}

// sealWithEntropy is Seal with all of its randomness given (spec section 9). For test vectors only.
func sealWithEntropy(args SealArgs, ent []byte) ([]byte, error) {
	s := &streamEntropy{b: ent}
	out, err := sealWith(args, s)
	if err != nil {
		return nil, err
	}
	if err := s.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// sealEntropyLength is the number of bytes a seal consumes: 60 + 32 per recipient (64 in hybrid mode).
func sealEntropyLength(mode Mode, recipients int) int {
	if mode == ModeMlkem {
		return 60 + 32*recipients
	}
	return 60 + 64*recipients
}

// ParseEnvelope reads the structure of an envelope without decrypting it.
func ParseEnvelope(b []byte) (ParsedEnvelope, error) {
	if len(b) < 10 || !equalBytes(b[:4], envelopeMagic) {
		return ParsedEnvelope{}, errorf(CodeMalformedEnvelope, "not a QoreSeal envelope")
	}
	if b[4] != EnvelopeVersion {
		return ParsedEnvelope{}, errorf(CodeUnsupportedVersion, "unsupported envelope version %d", b[4])
	}
	mb := b[5]
	if (mb != modeHybridByte && mb != modeMlkemByte) || b[6] != AlgorithmMLKEM1024 || b[7] != kdfHkdfSha256 || b[8] != aeadAes256Gcm {
		return ParsedEnvelope{}, errorf(CodeUnsupportedAlgorithm, "unsupported mode or algorithm in the envelope")
	}
	flags := b[9]
	if flags&^flagAnonymous != 0 {
		return ParsedEnvelope{}, errorf(CodeMalformedEnvelope, "unknown envelope flags")
	}
	if len(b) < fixedHeaderLength {
		return ParsedEnvelope{}, errorf(CodeMalformedEnvelope, "truncated envelope")
	}
	mode := ModeHybrid
	if mb == modeMlkemByte {
		mode = ModeMlkem
	}
	n := int(b[26])<<8 | int(b[27])
	if n == 0 || n > MaxRecipients {
		return ParsedEnvelope{}, errorf(CodeMalformedEnvelope, "invalid recipient count %d", n)
	}
	headerLength := fixedHeaderLength + n*EntryLength(mode) + nonceLength
	if len(b) < headerLength+tagLength {
		return ParsedEnvelope{}, errorf(CodeMalformedEnvelope, "truncated envelope")
	}
	entries := make([]EnvelopeEntry, 0, n)
	off := fixedHeaderLength
	take := func(k int) []byte {
		out := clone(b[off : off+k])
		off += k
		return out
	}
	for i := 0; i < n; i++ {
		e := EnvelopeEntry{Hint: take(hintLength), MlkemCiphertext: take(MLKEM1024CiphertextLength)}
		if mode == ModeHybrid {
			e.X25519Ciphertext = take(32)
		}
		e.WrappedKey = take(wrappedKeyLength)
		entries = append(entries, e)
	}
	return ParsedEnvelope{
		Version:    EnvelopeVersion,
		Mode:       mode,
		Anonymous:  flags&flagAnonymous != 0,
		Salt:       clone(b[10:26]),
		Entries:    entries,
		Nonce:      clone(b[off : off+nonceLength]),
		Ciphertext: clone(b[headerLength:]),
		Header:     clone(b[:headerLength]),
	}, nil
}

// Open decrypts an envelope with the recipient's keys.
func Open(args OpenArgs) ([]byte, error) {
	if err := checkChainID(args.ChainID); err != nil {
		return nil, err
	}
	if err := checkPurpose(args.Purpose, "purpose"); err != nil {
		return nil, err
	}
	if err := checkKeyPair(args.Keys); err != nil {
		return nil, err
	}
	env, err := ParseEnvelope(args.Envelope)
	if err != nil {
		return nil, err
	}
	fixed := env.Header[:fixedHeaderLength]
	var candidates []EnvelopeEntry
	if env.Anonymous {
		candidates = env.Entries
	} else {
		mine := RecipientHint(env.Salt, args.Keys.MlkemPublicKey)
		for _, e := range env.Entries {
			if equalBytes(e.Hint, mine) {
				candidates = append(candidates, e)
			}
		}
	}
	if len(candidates) == 0 {
		return nil, errorf(CodeNotARecipient, "the envelope has no entry for this key")
	}
	var dek []byte
	for _, e := range candidates {
		if dek = openEntry(args, env, fixed, e); dek != nil {
			break
		}
	}
	if dek == nil {
		return nil, errorf(CodeDecryptionFailed, "no entry of the envelope opens with this key, chain id and purpose")
	}
	pt, err := gcmFor(dek).Open(nil, env.Nonce, env.Ciphertext, concat(env.Header, args.AAD))
	if err != nil {
		return nil, errorf(CodeDecryptionFailed, "the payload does not authenticate")
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}

func openEntry(args OpenArgs, env ParsedEnvelope, fixed []byte, e EnvelopeEntry) []byte {
	ssK, err := MlkemDecapsulate(args.Keys.MlkemSecretKey, e.MlkemCiphertext)
	if err != nil {
		return nil
	}
	shared := ssK
	if env.Mode == ModeHybrid {
		ssX, err := X25519Agree(args.Keys.X25519SecretKey, e.X25519Ciphertext)
		if err != nil {
			return nil
		}
		if shared, err = HybridSharedSecret(ssK, ssX, e.X25519Ciphertext, args.Keys.X25519PublicKey); err != nil {
			return nil
		}
	}
	kek, err := DeriveKey(shared, args.ChainID, args.Purpose, env.Salt)
	if err != nil {
		return nil
	}
	dek, err := gcmFor(kek).Open(nil, zeroNonce, e.WrappedKey, concat(fixed, e.Hint, e.MlkemCiphertext, e.X25519Ciphertext))
	if err != nil {
		return nil
	}
	return dek
}

var textEncoding = base64.RawURLEncoding.Strict()

// EnvelopeToText returns "qoreseal:" + base64url(envelope), without padding.
func EnvelopeToText(envelope []byte) string {
	return EnvelopeTextPrefix + textEncoding.EncodeToString(envelope)
}

// EnvelopeFromText is the inverse of EnvelopeToText; strict about the alphabet, padding and trailing bits.
func EnvelopeFromText(text string) ([]byte, error) {
	if !strings.HasPrefix(text, EnvelopeTextPrefix) {
		return nil, errorf(CodeMalformedEnvelope, "text form must start with %q", EnvelopeTextPrefix)
	}
	s := text[len(EnvelopeTextPrefix):]
	if strings.ContainsAny(s, "\r\n") {
		return nil, errorf(CodeMalformedEnvelope, "invalid base64url in the text form")
	}
	b, err := textEncoding.DecodeString(s)
	if err != nil {
		return nil, errorf(CodeMalformedEnvelope, "invalid base64url in the text form")
	}
	return b, nil
}
