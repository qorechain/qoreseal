// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vecKey struct {
	Seed               string `json:"seed"`
	MlkemPublicKey     string `json:"mlkemPublicKey"`
	MlkemSecretKeySha3 string `json:"mlkemSecretKeySha3"`
	X25519PublicKey    string `json:"x25519PublicKey"`
	X25519SecretKey    string `json:"x25519SecretKey"`
}

type vecEnvelope struct {
	Name       string `json:"name"`
	Mode       Mode   `json:"mode"`
	Anonymous  bool   `json:"anonymous"`
	Recipients []int  `json:"recipients"`
	Plaintext  string `json:"plaintext"`
	AAD        string `json:"aad"`
	Entropy    string `json:"entropy"`
	Size       int    `json:"size"`
	Envelope   string `json:"envelope"`
	Text       string `json:"text"`
}

type vecNegative struct {
	Name     string  `json:"name"`
	Base     string  `json:"base"`
	Key      int     `json:"key"`
	ChainID  *string `json:"chainId"`
	Purpose  *string `json:"purpose"`
	AAD      *string `json:"aad"`
	Flip     *int    `json:"flip"`
	Set      []int   `json:"set"`
	Truncate *int    `json:"truncate"`
	Error    string  `json:"error"`
}

type vectorFile struct {
	Format        string   `json:"format"`
	ChainID       string   `json:"chainId"`
	Purpose       string   `json:"purpose"`
	Keys          []vecKey `json:"keys"`
	MnemonicSeeds []struct {
		Mnemonic           string `json:"mnemonic"`
		Passphrase         string `json:"passphrase"`
		Index              uint32 `json:"index"`
		Seed               string `json:"seed"`
		MlkemPublicKeySha3 string `json:"mlkemPublicKeySha3"`
	} `json:"mnemonicSeeds"`
	Encapsulation struct {
		Recipient    int    `json:"recipient"`
		M            string `json:"m"`
		Ciphertext   string `json:"ciphertext"`
		SharedSecret string `json:"sharedSecret"`
	} `json:"encapsulation"`
	X25519 struct {
		Recipient          int    `json:"recipient"`
		EphemeralSecretKey string `json:"ephemeralSecretKey"`
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		SharedSecret       string `json:"sharedSecret"`
	} `json:"x25519"`
	Hybrid struct {
		Label              string `json:"label"`
		MlkemSharedSecret  string `json:"mlkemSharedSecret"`
		X25519SharedSecret string `json:"x25519SharedSecret"`
		X25519Ciphertext   string `json:"x25519Ciphertext"`
		X25519PublicKey    string `json:"x25519PublicKey"`
		Shared             string `json:"shared"`
	} `json:"hybrid"`
	Kdf []struct {
		Shared  string `json:"shared"`
		ChainID string `json:"chainId"`
		Purpose string `json:"purpose"`
		Salt    string `json:"salt"`
		Info    string `json:"info"`
		Key     string `json:"key"`
	} `json:"kdf"`
	Hint struct {
		Salt      string `json:"salt"`
		Recipient int    `json:"recipient"`
		Hint      string `json:"hint"`
	} `json:"hint"`
	Envelopes    []vecEnvelope `json:"envelopes"`
	Negative     []vecNegative `json:"negative"`
	TextNegative []struct {
		Name  string `json:"name"`
		Text  string `json:"text"`
		Error string `json:"error"`
	} `json:"textNegative"`
	Card struct {
		Mnemonic      string          `json:"mnemonic"`
		Address       string          `json:"address"`
		PqPublicKey   string          `json:"pqPublicKey"`
		SealKeysIndex uint32          `json:"sealKeysIndex"`
		Text          string          `json:"text"`
		Card          json.RawMessage `json:"card"`
		Negative      []struct {
			Name            string  `json:"name"`
			ChainID         *string `json:"chainId"`
			MlkemKey        *int    `json:"mlkemKey"`
			X25519PublicKey *string `json:"x25519PublicKey"`
			Address         *string `json:"address"`
			Error           string  `json:"error"`
		} `json:"negative"`
	} `json:"card"`
	Registry struct {
		Sender   string `json:"sender"`
		Register struct {
			TypeURL string `json:"typeUrl"`
			Value   string `json:"value"`
		} `json:"register"`
		Remove struct {
			TypeURL string `json:"typeUrl"`
			Value   string `json:"value"`
		} `json:"remove"`
	} `json:"registry"`
	Epoch struct {
		Purpose    string `json:"purpose"`
		Epoch      uint64 `json:"epoch"`
		Key        string `json:"key"`
		Payload    string `json:"payload"`
		Recipients []int  `json:"recipients"`
		Entropy    string `json:"entropy"`
		Envelope   string `json:"envelope"`
	} `json:"epoch"`
	Batch struct {
		Epoch                uint64 `json:"epoch"`
		Key                  string `json:"key"`
		Context              string `json:"context"`
		BatchIndex           uint64 `json:"batchIndex"`
		Data                 string `json:"data"`
		Entropy              string `json:"entropy"`
		Blob                 string `json:"blob"`
		CiphertextCommitment string `json:"ciphertextCommitment"`
		PlaintextCommitment  string `json:"plaintextCommitment"`
	} `json:"batch"`
	Sizes []struct {
		Mode            Mode `json:"mode"`
		Recipients      int  `json:"recipients"`
		PlaintextLength int  `json:"plaintextLength"`
		Size            int  `json:"size"`
	} `json:"sizes"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "vectors", "qoreseal-v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if v.Format != "qoreseal-vectors-v1" {
		t.Fatalf("unexpected vectors format %q", v.Format)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vectors: %v", err)
	}
	return b
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func codeOf(err error) string {
	if err == nil {
		return "none"
	}
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return "foreign: " + err.Error()
}

func wantCode(t *testing.T, err error, code, what string) {
	t.Helper()
	if got := codeOf(err); got != code {
		t.Fatalf("%s: expected %s, got %s (%v)", what, code, got, err)
	}
}

func eqHex(t *testing.T, got []byte, want, what string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s: got %x, want %s", what, got, want)
	}
}
