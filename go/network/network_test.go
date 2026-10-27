// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qoreseal "github.com/qorechain/qoreseal/go"
	"github.com/qorechain/qoreseal/go/network"
	qoresign "github.com/qorechain/qoresign/go"
)

const (
	chain    = "qorechain-diana"
	mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if !qoreseal.IsCode(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

type route struct {
	status int
	body   any
}

func server(t *testing.T, routes map[string]route) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt, ok := routes[r.URL.Path]
		if !ok {
			rt = route{404, map[string]any{"code": 5, "message": "Not Found"}}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rt.status)
		_ = json.NewEncoder(w).Encode(rt.body)
	}))
	t.Cleanup(s.Close)
	return s
}

type fixture struct {
	address string
	keys    qoreseal.SealKeyPair
	card    qoreseal.RecipientCard
	kemBody map[string]any
	pqBody  map[string]any
}

func setup(t *testing.T) fixture {
	classical := must(qoresign.DeriveClassicalKey(mnemonic, qoresign.DeriveClassicalOptions{}))
	address := must(qoresign.AddressFromPublicKey(classical.PublicKey, qoresign.Secp256k1)).Bech32
	pq := must(qoresign.DeriveCanonicalPqKey(mnemonic, address))
	keys := must(qoreseal.DeriveSealKeys(mnemonic, qoreseal.MnemonicOptions{}))
	card := must(qoreseal.SignRecipientCard(qoreseal.SignRecipientCardArgs{
		ChainID: chain, Address: address, Keys: keys, ClassicalKey: classical, PqKey: pq,
	}))
	return fixture{
		address: address, keys: keys, card: card,
		kemBody: map[string]any{"found": true, "key": map[string]any{
			"address": address, "algorithm_id": 2, "algorithm_name": "ml-kem-1024",
			"public_key": base64.StdEncoding.EncodeToString(keys.MlkemPublicKey), "registered_height": "1234",
		}},
		pqBody: map[string]any{"found": true, "account": map[string]any{
			"public_key": base64.StdEncoding.EncodeToString(pq.PublicKey), "algorithm_id": 1, "key_type": "hybrid", "possession_proven": true,
		}},
	}
}

func TestFetchKemKey(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	s := server(t, map[string]route{"/qorechain/pqc/v1/kem/" + f.address: {200, f.kemBody}})
	st := must(network.NewClient(s.URL).FetchKemKey(ctx, f.address))
	if !st.Registered || st.RegisteredHeight != 1234 || st.AlgorithmID != 2 || st.AlgorithmName != "ml-kem-1024" {
		t.Fatalf("%+v", st)
	}
	if qoreseal.ToHex(st.PublicKey) != qoreseal.ToHex(f.keys.MlkemPublicKey) {
		t.Fatal("public key")
	}

	none := server(t, map[string]route{"/qorechain/pqc/v1/kem/" + f.address: {200, map[string]any{"found": false}}})
	st = must(network.NewClient(none.URL).FetchKemKey(ctx, f.address))
	if st.Registered {
		t.Fatal("expected not registered")
	}
	_, err := network.NewClient(none.URL).FetchMlkemPublicKey(ctx, f.address)
	wantCode(t, err, qoreseal.CodeKemKeyNotRegistered)

	_, err = network.NewClient(server(t, nil).URL).FetchKemKey(ctx, f.address)
	wantCode(t, err, qoreseal.CodeKemRegistryUnavailable)
	notImpl := server(t, map[string]route{"/qorechain/pqc/v1/kem/" + f.address: {501, map[string]any{"code": 12}}})
	_, err = network.NewClient(notImpl.URL).FetchKemKey(ctx, f.address)
	wantCode(t, err, qoreseal.CodeKemRegistryUnavailable)
	_, err = network.NewClient("http://127.0.0.1:1").FetchKemKey(ctx, f.address)
	wantCode(t, err, qoreseal.CodeNetworkUnavailable)
}

func TestResolveAndSeal(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	s := server(t, map[string]route{
		"/qorechain/pqc/v1/kem/" + f.address:     {200, f.kemBody},
		"/qorechain/pqc/v1/account/" + f.address: {200, f.pqBody},
	})
	c := network.NewClient(s.URL)
	r := must(c.ResolveRecipient(ctx, network.ResolveArgs{ChainID: chain, Address: f.address, Card: &f.card}))
	if qoreseal.ToHex(r.X25519PublicKey) != qoreseal.ToHex(f.keys.X25519PublicKey) {
		t.Fatal("x25519")
	}
	_, err := c.ResolveRecipient(ctx, network.ResolveArgs{ChainID: chain, Address: f.address})
	wantCode(t, err, qoreseal.CodeRecipientNeedsX25519)
	kemOnly := must(c.ResolveRecipient(ctx, network.ResolveArgs{ChainID: chain, Address: f.address, Mode: qoreseal.ModeMlkem}))
	if kemOnly.X25519PublicKey != nil {
		t.Fatal("mlkem recipient has an x25519 key")
	}
	for _, mode := range []qoreseal.Mode{qoreseal.ModeHybrid, qoreseal.ModeMlkem} {
		env := must(c.SealToAddresses(ctx, network.SealToArgs{ChainID: chain, Purpose: "chat", Mode: mode,
			Recipients: []network.AddressRecipient{{Address: f.address, Card: &f.card}}, Plaintext: []byte("hi")}))
		pt := must(qoreseal.Open(qoreseal.OpenArgs{ChainID: chain, Purpose: "chat", Envelope: env, Keys: f.keys}))
		if string(pt) != "hi" {
			t.Fatal(string(pt))
		}
	}

	other := must(qoreseal.GenerateSealKeys())
	staleKem := map[string]any{"found": true, "key": map[string]any{
		"address": f.address, "algorithm_id": 2, "public_key": base64.StdEncoding.EncodeToString(other.MlkemPublicKey), "registered_height": "1",
	}}
	stale := server(t, map[string]route{
		"/qorechain/pqc/v1/kem/" + f.address:     {200, staleKem},
		"/qorechain/pqc/v1/account/" + f.address: {200, f.pqBody},
	})
	_, err = network.NewClient(stale.URL).ResolveRecipient(ctx, network.ResolveArgs{ChainID: chain, Address: f.address, Card: &f.card})
	wantCode(t, err, qoreseal.CodeCardInvalid)

	noPq := server(t, map[string]route{
		"/qorechain/pqc/v1/kem/" + f.address:     {200, f.kemBody},
		"/qorechain/pqc/v1/account/" + f.address: {200, map[string]any{"found": false}},
	})
	_, err = network.NewClient(noPq.URL).ResolveRecipient(ctx, network.ResolveArgs{ChainID: chain, Address: f.address, Card: &f.card})
	wantCode(t, err, qoreseal.CodeCardInvalid)
}
