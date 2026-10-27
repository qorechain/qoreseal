// SPDX-License-Identifier: Apache-2.0
//
// Behaviour beyond the vectors: random round trips, input checks, groups and batches.

package qoreseal

import (
	"bytes"
	"reflect"
	"sync"
	"testing"
)

const testChain = "qorechain-diana"

func genKeys(t *testing.T) SealKeyPair {
	t.Helper()
	return must(GenerateSealKeys())
}

func TestRoundTrips(t *testing.T) {
	alice, bob, carol := genKeys(t), genKeys(t), genKeys(t)
	for _, mode := range []Mode{ModeHybrid, ModeMlkem} {
		for _, anonymous := range []bool{false, true} {
			env, err := Seal(SealArgs{ChainID: testChain, Purpose: "chat", Mode: mode, Anonymous: anonymous,
				Recipients: []SealRecipient{RecipientOf(alice), RecipientOf(bob)}, Plaintext: []byte("hello")})
			if err != nil {
				t.Fatal(err)
			}
			if len(env) != EnvelopeSize(mode, 2, 5) {
				t.Fatalf("size %d", len(env))
			}
			for _, k := range []SealKeyPair{alice, bob} {
				pt, err := Open(OpenArgs{ChainID: testChain, Purpose: "chat", Envelope: env, Keys: k})
				if err != nil || string(pt) != "hello" {
					t.Fatalf("%s/%v: %v", mode, anonymous, err)
				}
			}
			_, err = Open(OpenArgs{ChainID: testChain, Purpose: "chat", Envelope: env, Keys: carol})
			want := CodeNotARecipient
			if anonymous {
				want = CodeDecryptionFailed
			}
			wantCode(t, err, want, "outsider")
		}
	}
	args := SealArgs{ChainID: testChain, Purpose: "chat", Recipients: []SealRecipient{RecipientOf(alice)}, Plaintext: []byte("x")}
	if bytes.Equal(must(Seal(args)), must(Seal(args))) {
		t.Fatal("two seals are identical")
	}
	empty := must(Seal(SealArgs{ChainID: testChain, Purpose: "chat", Recipients: []SealRecipient{RecipientOf(alice)}}))
	if pt := must(Open(OpenArgs{ChainID: testChain, Purpose: "chat", Envelope: empty, Keys: alice})); len(pt) != 0 {
		t.Fatal("empty plaintext")
	}
}

func TestHybridNeedsX25519(t *testing.T) {
	alice := genKeys(t)
	onlyKem := SealRecipient{MlkemPublicKey: alice.MlkemPublicKey}
	_, err := Seal(SealArgs{ChainID: testChain, Purpose: "chat", Recipients: []SealRecipient{onlyKem}, Plaintext: []byte("x")})
	wantCode(t, err, CodeRecipientNeedsX25519, "default hybrid")
	env := must(Seal(SealArgs{ChainID: testChain, Purpose: "chat", Mode: ModeMlkem, Recipients: []SealRecipient{onlyKem}, Plaintext: []byte("x")}))
	if must(ParseEnvelope(env)).Mode != ModeMlkem {
		t.Fatal("mode")
	}
}

func TestInputChecks(t *testing.T) {
	alice := genKeys(t)
	bad := append([]byte(nil), alice.MlkemPublicKey...)
	bad[0], bad[1] = 0xff, 0x0f
	wantCode(t, ValidateMlkemPublicKey(bad), CodeInvalidKey, "modulus")
	wantCode(t, ValidateMlkemPublicKey(make([]byte, 1568)), CodeInvalidKey, "zero key")
	wantCode(t, ValidateMlkemPublicKey(make([]byte, 1567)), CodeInvalidKey, "length")

	r := RecipientOf(alice)
	seal := func(mod func(*SealArgs)) error {
		a := SealArgs{ChainID: testChain, Purpose: "chat", Recipients: []SealRecipient{r}, Plaintext: []byte("x")}
		mod(&a)
		_, err := Seal(a)
		return err
	}
	wantCode(t, seal(func(a *SealArgs) {
		a.Recipients = []SealRecipient{{MlkemPublicKey: bad, X25519PublicKey: r.X25519PublicKey}}
	}), CodeInvalidKey, "bad kem")
	lowOrder := make([]byte, 32)
	lowOrder[0] = 1
	wantCode(t, seal(func(a *SealArgs) {
		a.Recipients = []SealRecipient{{MlkemPublicKey: r.MlkemPublicKey, X25519PublicKey: lowOrder}}
	}), CodeInvalidKey, "low order")
	wantCode(t, seal(func(a *SealArgs) {
		a.Recipients = []SealRecipient{{MlkemPublicKey: r.MlkemPublicKey, X25519PublicKey: make([]byte, 32)}}
	}), CodeInvalidKey, "zero x25519")
	wantCode(t, seal(func(a *SealArgs) { a.Recipients = nil }), CodeInvalidArgument, "no recipients")
	wantCode(t, seal(func(a *SealArgs) { a.ChainID = "bad|chain" }), CodeInvalidArgument, "chain id")
	wantCode(t, seal(func(a *SealArgs) { a.Purpose = "" }), CodeInvalidArgument, "empty purpose")
	wantCode(t, seal(func(a *SealArgs) { a.Purpose = "a b" }), CodeInvalidArgument, "purpose")
	wantCode(t, seal(func(a *SealArgs) { a.Mode = "rsa" }), CodeInvalidArgument, "mode")
	_, err := SealKeysFromSeed(make([]byte, 31))
	wantCode(t, err, CodeInvalidArgument, "seed")
	_, err = DeriveSealKeys("not a mnemonic", MnemonicOptions{})
	wantCode(t, err, CodeInvalidArgument, "mnemonic")
	_, err = DeriveSealKeys("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", MnemonicOptions{Index: 1 << 31})
	wantCode(t, err, CodeInvalidArgument, "index")
}

func TestEntropyExactness(t *testing.T) {
	alice := genKeys(t)
	args := SealArgs{ChainID: testChain, Purpose: "chat", Recipients: []SealRecipient{RecipientOf(alice)}, Plaintext: []byte("x")}
	n := sealEntropyLength(ModeHybrid, 1)
	if n != 124 {
		t.Fatal(n)
	}
	_, err := sealWithEntropy(args, bytes.Repeat([]byte{7}, n-1))
	wantCode(t, err, CodeInvalidArgument, "short entropy")
	_, err = sealWithEntropy(args, bytes.Repeat([]byte{7}, n+1))
	wantCode(t, err, CodeInvalidArgument, "long entropy")
	_, err = sealBatchWithEntropy(SealBatchArgs{EpochKey: EpochKey{Epoch: 1, Key: make([]byte, 32)}, Context: "c", Data: nil}, make([]byte, 43))
	wantCode(t, err, CodeInvalidArgument, "batch entropy")
}

func TestParseMalformed(t *testing.T) {
	_, err := ParseEnvelope(make([]byte, 3))
	wantCode(t, err, CodeMalformedEnvelope, "short")
	_, err = ParseEnvelope([]byte("QSEL\x01\x01\x02\x01\x01\x00"))
	wantCode(t, err, CodeMalformedEnvelope, "header only")
	_, err = EnvelopeFromText("qoreseal:AAAA\nAAAA")
	wantCode(t, err, CodeMalformedEnvelope, "newline")
}

func TestRegistryHelpers(t *testing.T) {
	if s, ok := DescribeKemRegistryError("pqc", 254); !ok || s == "" {
		t.Fatal("254")
	}
	if _, ok := DescribeKemRegistryError("sdk", 254); ok {
		t.Fatal("sdk")
	}
	_, err := BuildRegisterKemKeyMessage("nope", genKeys(t).MlkemPublicKey)
	wantCode(t, err, CodeInvalidArgument, "sender")
}

func TestGroups(t *testing.T) {
	alice, bob, carol := genKeys(t), genKeys(t), genKeys(t)
	const purpose = "epoch-key:demo-rollup"
	mgr := must(NewEpochKeyManager(EpochKeyManagerOptions{ChainID: testChain, Purpose: purpose,
		Members: []Member{{"alice", RecipientOf(alice)}, {"bob", RecipientOf(bob)}}}))
	if mgr.Epoch() != 1 {
		t.Fatal(mgr.Epoch())
	}
	codec := must(NewPrivateBatchCodec("demo-rollup", mgr))
	b1 := must(codec.Seal(1, []byte("batch one")))

	join := must(mgr.AddMember("carol", RecipientOf(carol)))
	if join.Epoch != 2 {
		t.Fatal(join.Epoch)
	}
	carolKey := must(OpenEpochKey(testChain, purpose, join.Envelope, carol))
	if carolKey.Epoch != 2 {
		t.Fatal(carolKey.Epoch)
	}
	_, err := OpenBatch(b1.Blob, KeysFromList([]EpochKey{carolKey}))
	wantCode(t, err, CodeUnknownEpoch, "carol reads epoch 1")

	leave := must(mgr.RemoveMember("bob"))
	if leave.Epoch != 3 || !reflect.DeepEqual(leave.Members, []string{"alice", "carol"}) {
		t.Fatalf("%+v", leave.Members)
	}
	_, err = OpenEpochKey(testChain, purpose, leave.Envelope, bob)
	wantCode(t, err, CodeNotARecipient, "bob after removal")
	b3 := must(codec.Seal(3, []byte("batch three")))
	aliceKey := must(OpenEpochKey(testChain, purpose, leave.Envelope, alice))
	opened := must(OpenBatch(b3.Blob, KeysFromList([]EpochKey{aliceKey})))
	if string(opened.Data) != "batch three" || !bytes.Equal(opened.PlaintextCommitment, b3.PlaintextCommitment) {
		t.Fatal("batch three")
	}
	if must(codec.Open(b1.Blob)).BatchIndex != 1 {
		t.Fatal("codec open")
	}
	_, err = mgr.RemoveMember("nobody")
	wantCode(t, err, CodeInvalidArgument, "unknown member")

	restored := must(NewEpochKeyManager(EpochKeyManagerOptions{ChainID: testChain, Purpose: purpose, History: mgr.ExportKeys()}))
	if restored.Epoch() != 3 {
		t.Fatal(restored.Epoch())
	}
	k1, _ := restored.KeyFor(1)
	k1b, _ := mgr.KeyFor(1)
	if !bytes.Equal(k1, k1b) {
		t.Fatal("history")
	}
	_, err = restored.Distribution()
	wantCode(t, err, CodeInvalidArgument, "no members")

	_, err = NewEpochKeyManager(EpochKeyManagerOptions{ChainID: testChain, Purpose: purpose,
		Members: []Member{{"x", SealRecipient{MlkemPublicKey: alice.MlkemPublicKey}}}})
	wantCode(t, err, CodeRecipientNeedsX25519, "hybrid member without x25519")

	// Concurrent use.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := mgr.Rotate(); err != nil {
				t.Error(err)
			}
			_ = mgr.CurrentKey()
		}()
	}
	wg.Wait()
	if mgr.Epoch() != 11 {
		t.Fatalf("epoch after concurrent rotations: %d", mgr.Epoch())
	}
}

func TestBatchNegatives(t *testing.T) {
	ek := EpochKey{Epoch: 4, Key: bytes.Repeat([]byte{9}, 32)}
	b := must(SealBatch(SealBatchArgs{EpochKey: ek, Context: "demo-rollup", BatchIndex: 2, Data: []byte("data")}))
	keys := KeysFromList([]EpochKey{ek})
	mut := func(i int, f func(byte) byte) []byte {
		out := append([]byte(nil), b.Blob...)
		out[i] = f(out[i])
		return out
	}
	_, err := OpenBatch(mut(len(b.Blob)-1, func(x byte) byte { return x ^ 1 }), keys)
	wantCode(t, err, CodeDecryptionFailed, "tampered ciphertext")
	_, err = OpenBatch(mut(21, func(x byte) byte { return x ^ 1 }), keys)
	wantCode(t, err, CodeDecryptionFailed, "tampered index")
	_, err = OpenBatch(mut(4, func(byte) byte { return 9 }), keys)
	wantCode(t, err, CodeUnsupportedVersion, "version")
	_, err = OpenBatch(mut(5, func(byte) byte { return 2 }), keys)
	wantCode(t, err, CodeUnsupportedAlgorithm, "cipher")
	_, err = OpenBatch([]byte("nope"), keys)
	wantCode(t, err, CodeMalformedBatch, "foreign")
	_, err = OpenBatch(b.Blob, KeysFromList([]EpochKey{{Epoch: 4, Key: make([]byte, 32)}}))
	wantCode(t, err, CodeDecryptionFailed, "wrong key")
	_, err = SealBatch(SealBatchArgs{EpochKey: ek, Context: "bad context", BatchIndex: 1, Data: []byte("x")})
	wantCode(t, err, CodeInvalidArgument, "context")
	_, err = SealBatch(SealBatchArgs{EpochKey: EpochKey{Epoch: 0, Key: ek.Key}, Context: "c", Data: []byte("x")})
	wantCode(t, err, CodeInvalidArgument, "epoch 0")
}
