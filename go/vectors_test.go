// SPDX-License-Identifier: Apache-2.0
//
// The Go module against vectors/qoreseal-v1.json.

package qoreseal

import (
	"crypto/sha3"
	"encoding/json"
	"reflect"
	"testing"

	qoresign "github.com/qorechain/qoresign/go"
)

func vectorKeys(t *testing.T, v vectorFile) []SealKeyPair {
	out := make([]SealKeyPair, len(v.Keys))
	for i, k := range v.Keys {
		out[i] = must(SealKeysFromSeed(mustHex(t, k.Seed)))
	}
	return out
}

func TestVectorKeys(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	for i, k := range v.Keys {
		eqHex(t, keys[i].MlkemPublicKey, k.MlkemPublicKey, "mlkem public key")
		h := sha3.Sum256(keys[i].MlkemSecretKey)
		eqHex(t, h[:], k.MlkemSecretKeySha3, "mlkem secret key")
		eqHex(t, keys[i].X25519PublicKey, k.X25519PublicKey, "x25519 public key")
		eqHex(t, keys[i].X25519SecretKey, k.X25519SecretKey, "x25519 secret key")
	}
}

func TestVectorMnemonicSeeds(t *testing.T) {
	v := loadVectors(t)
	for _, m := range v.MnemonicSeeds {
		seed := must(SealSeedFromMnemonic(m.Mnemonic, MnemonicOptions{Passphrase: m.Passphrase, Index: m.Index}))
		eqHex(t, seed, m.Seed, "mnemonic seed")
		h := sha3.Sum256(must(SealKeysFromSeed(seed)).MlkemPublicKey)
		eqHex(t, h[:], m.MlkemPublicKeySha3, "mnemonic key")
	}
}

func TestVectorPrimitives(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)

	e := v.Encapsulation
	ct, ss, err := mlkemEncapsulateDerand(keys[e.Recipient].MlkemPublicKey, mustHex(t, e.M))
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, ct, e.Ciphertext, "encapsulation ciphertext")
	eqHex(t, ss, e.SharedSecret, "encapsulation secret")
	eqHex(t, must(MlkemDecapsulate(keys[e.Recipient].MlkemSecretKey, ct)), e.SharedSecret, "decapsulation")

	x := v.X25519
	eqHex(t, must(X25519PublicKey(mustHex(t, x.EphemeralSecretKey))), x.EphemeralPublicKey, "x25519 ephemeral")
	eqHex(t, must(X25519Agree(mustHex(t, x.EphemeralSecretKey), keys[x.Recipient].X25519PublicKey)), x.SharedSecret, "x25519 sender")
	eqHex(t, must(X25519Agree(keys[x.Recipient].X25519SecretKey, mustHex(t, x.EphemeralPublicKey))), x.SharedSecret, "x25519 recipient")

	h := v.Hybrid
	if h.Label != HybridLabel {
		t.Fatalf("hybrid label %q", h.Label)
	}
	eqHex(t, must(HybridSharedSecret(mustHex(t, h.MlkemSharedSecret), mustHex(t, h.X25519SharedSecret),
		mustHex(t, h.X25519Ciphertext), mustHex(t, h.X25519PublicKey))), h.Shared, "hybrid shared")

	for _, k := range v.Kdf {
		if info := must(KdfInfo(k.ChainID, k.Purpose)); info != k.Info {
			t.Fatalf("kdf info %q, want %q", info, k.Info)
		}
		eqHex(t, must(DeriveKey(mustHex(t, k.Shared), k.ChainID, k.Purpose, mustHex(t, k.Salt))), k.Key, "derived key")
	}
	eqHex(t, RecipientHint(mustHex(t, v.Hint.Salt), keys[v.Hint.Recipient].MlkemPublicKey), v.Hint.Hint, "hint")
}

func TestVectorEnvelopes(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	for _, e := range v.Envelopes {
		t.Run(e.Name, func(t *testing.T) {
			var recipients []SealRecipient
			for _, i := range e.Recipients {
				recipients = append(recipients, RecipientOf(keys[i]))
			}
			if n := sealEntropyLength(e.Mode, len(e.Recipients)); n != len(mustHex(t, e.Entropy)) {
				t.Fatalf("entropy length %d", n)
			}
			env, err := sealWithEntropy(SealArgs{
				ChainID: v.ChainID, Purpose: v.Purpose, Mode: e.Mode, Anonymous: e.Anonymous,
				Recipients: recipients, Plaintext: mustHex(t, e.Plaintext), AAD: mustHex(t, e.AAD),
			}, mustHex(t, e.Entropy))
			if err != nil {
				t.Fatal(err)
			}
			eqHex(t, env, e.Envelope, "envelope")
			if len(env) != e.Size || EnvelopeSize(e.Mode, len(e.Recipients), len(mustHex(t, e.Plaintext))) != e.Size {
				t.Fatalf("size %d, want %d", len(env), e.Size)
			}
			if EnvelopeToText(env) != e.Text {
				t.Fatal("text form differs")
			}
			eqHex(t, must(EnvelopeFromText(e.Text)), e.Envelope, "text decode")
			for _, i := range e.Recipients {
				pt, err := Open(OpenArgs{ChainID: v.ChainID, Purpose: v.Purpose, Envelope: env, Keys: keys[i], AAD: mustHex(t, e.AAD)})
				if err != nil {
					t.Fatalf("recipient %d: %v", i, err)
				}
				eqHex(t, pt, e.Plaintext, "plaintext")
			}
			p := must(ParseEnvelope(env))
			if p.Mode != e.Mode || p.Anonymous != e.Anonymous || len(p.Entries) != len(e.Recipients) {
				t.Fatalf("parsed %+v", p.Mode)
			}
		})
	}
}

func TestVectorNegative(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	byName := map[string]vecEnvelope{}
	for _, e := range v.Envelopes {
		byName[e.Name] = e
	}
	for _, n := range v.Negative {
		base := byName[n.Base]
		env := mustHex(t, base.Envelope)
		if n.Flip != nil {
			env[*n.Flip] ^= 0x01
		}
		if len(n.Set) == 2 {
			env[n.Set[0]] = byte(n.Set[1])
		}
		if n.Truncate != nil {
			env = env[:*n.Truncate]
		}
		args := OpenArgs{ChainID: v.ChainID, Purpose: v.Purpose, Envelope: env, Keys: keys[n.Key], AAD: mustHex(t, base.AAD)}
		if n.ChainID != nil {
			args.ChainID = *n.ChainID
		}
		if n.Purpose != nil {
			args.Purpose = *n.Purpose
		}
		if n.AAD != nil {
			args.AAD = mustHex(t, *n.AAD)
		}
		_, err := Open(args)
		wantCode(t, err, n.Error, n.Name)
	}
	for _, tn := range v.TextNegative {
		_, err := EnvelopeFromText(tn.Text)
		wantCode(t, err, tn.Error, tn.Name)
	}
	for _, s := range v.Sizes {
		if EnvelopeSize(s.Mode, s.Recipients, s.PlaintextLength) != s.Size {
			t.Fatalf("size table %+v", s)
		}
	}
}

func jsonValue(t *testing.T, b []byte) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVectorCard(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)
	c := v.Card
	var card RecipientCard
	if err := json.Unmarshal(c.Card, &card); err != nil {
		t.Fatal(err)
	}
	classical := must(qoresign.DeriveClassicalKey(c.Mnemonic, qoresign.DeriveClassicalOptions{}))
	pq := must(qoresign.DeriveCanonicalPqKey(c.Mnemonic, c.Address))
	eqHex(t, pq.PublicKey, c.PqPublicKey, "pq public key")
	sealKeys := must(DeriveSealKeys(c.Mnemonic, MnemonicOptions{Index: c.SealKeysIndex}))

	signed, err := SignRecipientCard(SignRecipientCardArgs{
		ChainID: v.ChainID, Address: c.Address, Keys: sealKeys, ClassicalKey: classical, PqKey: pq, IssuedAt: card.IssuedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if must(RecipientCardText(signed.RecipientCardFields)) != c.Text {
		t.Fatal("card text differs")
	}
	if !reflect.DeepEqual(jsonValue(t, must(json.Marshal(signed))), jsonValue(t, c.Card)) {
		t.Fatalf("signed card differs:\n%s", must(json.Marshal(signed)))
	}

	r, err := VerifyRecipientCard(VerifyRecipientCardArgs{
		Card: card, ChainID: v.ChainID, Address: c.Address, PqPublicKey: mustHex(t, c.PqPublicKey), MlkemPublicKey: sealKeys.MlkemPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, r.X25519PublicKey, ToHex(sealKeys.X25519PublicKey), "card x25519")

	for _, n := range c.Negative {
		cc := card
		args := VerifyRecipientCardArgs{Card: cc, ChainID: v.ChainID, PqPublicKey: mustHex(t, c.PqPublicKey), MlkemPublicKey: sealKeys.MlkemPublicKey}
		if n.X25519PublicKey != nil {
			args.Card.X25519PublicKey = *n.X25519PublicKey
		}
		if n.ChainID != nil {
			args.ChainID = *n.ChainID
		}
		if n.Address != nil {
			args.Address = *n.Address
		}
		if n.MlkemKey != nil {
			args.MlkemPublicKey = keys[*n.MlkemKey].MlkemPublicKey
		}
		_, err := VerifyRecipientCard(args)
		wantCode(t, err, n.Error, n.Name)
	}
}

func TestVectorRegistryEpochBatch(t *testing.T) {
	v := loadVectors(t)
	keys := vectorKeys(t, v)

	r := v.Registry
	sealKeys := must(DeriveSealKeys(v.Card.Mnemonic, MnemonicOptions{}))
	reg := must(BuildRegisterKemKeyMessage(r.Sender, sealKeys.MlkemPublicKey))
	if reg.TypeURL != r.Register.TypeURL {
		t.Fatal(reg.TypeURL)
	}
	eqHex(t, reg.Value, r.Register.Value, "register message")
	rem := must(BuildRemoveKemKeyMessage(r.Sender))
	if rem.TypeURL != r.Remove.TypeURL {
		t.Fatal(rem.TypeURL)
	}
	eqHex(t, rem.Value, r.Remove.Value, "remove message")

	e := v.Epoch
	ek := EpochKey{Epoch: e.Epoch, Key: mustHex(t, e.Key)}
	payload := must(EncodeEpochKey(ek))
	eqHex(t, payload, e.Payload, "epoch payload")
	var recipients []SealRecipient
	for _, i := range e.Recipients {
		recipients = append(recipients, RecipientOf(keys[i]))
	}
	env := must(sealWithEntropy(SealArgs{ChainID: v.ChainID, Purpose: e.Purpose, Recipients: recipients, Plaintext: payload}, mustHex(t, e.Entropy)))
	eqHex(t, env, e.Envelope, "epoch envelope")
	for _, i := range e.Recipients {
		got := must(OpenEpochKey(v.ChainID, e.Purpose, env, keys[i]))
		if got.Epoch != 1 {
			t.Fatal(got.Epoch)
		}
		eqHex(t, got.Key, e.Key, "epoch key")
	}

	b := v.Batch
	bk := EpochKey{Epoch: b.Epoch, Key: mustHex(t, b.Key)}
	sealed := must(sealBatchWithEntropy(SealBatchArgs{EpochKey: bk, Context: b.Context, BatchIndex: b.BatchIndex, Data: mustHex(t, b.Data)}, mustHex(t, b.Entropy)))
	eqHex(t, sealed.Blob, b.Blob, "batch blob")
	eqHex(t, sealed.CiphertextCommitment, b.CiphertextCommitment, "ciphertext commitment")
	eqHex(t, sealed.PlaintextCommitment, b.PlaintextCommitment, "plaintext commitment")
	opened := must(OpenBatch(sealed.Blob, KeysFromList([]EpochKey{bk})))
	eqHex(t, opened.Data, b.Data, "batch data")
	if opened.BatchIndex != 7 || opened.Context != b.Context {
		t.Fatal("batch header")
	}
	eqHex(t, opened.PlaintextCommitment, b.PlaintextCommitment, "opened commitment")
	if len(sealed.Blob) != BatchSize(len(b.Context), len(mustHex(t, b.Data))) {
		t.Fatal("batch size")
	}
}
