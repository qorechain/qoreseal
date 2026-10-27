// SPDX-License-Identifier: Apache-2.0
//
// End-to-end checks against a QoreChain testnet. Skipped unless
// QORE_LIVE_TEST=1 and QORE_TEST_MNEMONIC (a funded testnet account with a
// registered ML-DSA-87 key) are set. QORE_REST and QORE_CHAIN_ID override
// the endpoint and chain id. Never point this at mainnet: it refuses
// qorechain-vladi until that network has applied v3.2.5.

package qoreseal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	qoreseal "github.com/qorechain/qoreseal/go"
	"github.com/qorechain/qoreseal/go/network"
	qoresign "github.com/qorechain/qoresign/go"
	qsnet "github.com/qorechain/qoresign/go/network"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type liveEnv struct {
	rest      string
	chainID   string
	sign      *qsnet.Client
	seal      *network.Client
	address   string
	classical qoresign.ClassicalKey
	pq        qoresign.PqKeyPair
}

func liveSetup(t *testing.T) liveEnv {
	t.Helper()
	mnemonic := os.Getenv("QORE_TEST_MNEMONIC")
	if os.Getenv("QORE_LIVE_TEST") != "1" || mnemonic == "" {
		t.Skip("set QORE_LIVE_TEST=1 and QORE_TEST_MNEMONIC to run the live tests")
	}
	env := liveEnv{rest: os.Getenv("QORE_REST"), chainID: os.Getenv("QORE_CHAIN_ID")}
	if env.rest == "" {
		env.rest = "https://api-testnet.qore.host"
	}
	if env.chainID == "" {
		env.chainID = "qorechain-diana"
	}
	env.sign = qsnet.NewClient(env.rest)
	env.seal = network.NewClient(env.rest)
	if env.chainID == "qorechain-vladi" {
		h, err := env.sign.FetchAppliedPlanHeight(context.Background(), "v3.2.5")
		if err != nil || h == 0 {
			t.Fatal("qorechain-vladi has not applied v3.2.5: the KEM key registry is not available there yet")
		}
	}
	env.classical = must(qoresign.DeriveClassicalKey(mnemonic, qoresign.DeriveClassicalOptions{}))
	env.address = must(qoresign.AddressFromPublicKey(env.classical.PublicKey, qoresign.Secp256k1)).Bech32
	env.pq = must(qoresign.DeriveCanonicalPqKey(mnemonic, env.address))
	return env
}

func liveGet(ctx context.Context, url string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return res.StatusCode, nil
	}
	return res.StatusCode, json.NewDecoder(res.Body).Decode(out)
}

func authInfo(pubkey []byte, sequence, gasLimit uint64, feeAmount string) []byte {
	pk := qoresign.EncodeAny(qoresign.Any{TypeURL: "/cosmos.crypto.secp256k1.PubKey", Value: qoresign.LenField(1, pubkey)})
	modeInfo := qoresign.LenField(1, qoresign.VarintField(1, 1))
	signerInfo := qoresign.Concat(qoresign.LenField(1, pk), qoresign.LenField(2, modeInfo), qoresign.VarintField(3, sequence))
	coin := qoresign.Concat(qoresign.StringField(1, "uqor"), qoresign.StringField(2, feeAmount))
	fee := qoresign.Concat(qoresign.LenField(1, coin), qoresign.VarintField(2, gasLimit))
	return qoresign.Concat(qoresign.LenField(1, signerInfo), qoresign.LenField(2, fee))
}

// sendHybrid signs a one-message transaction hybrid with QoreSign, simulates
// it for the gas limit, broadcasts it and waits for it to commit.
func (e liveEnv) sendHybrid(ctx context.Context, t *testing.T, msg qoresign.Any) string {
	t.Helper()
	var info struct {
		Info *struct {
			AccountNumber string `json:"account_number"`
			Sequence      string `json:"sequence"`
		} `json:"info"`
	}
	if status, err := liveGet(ctx, e.rest+"/cosmos/auth/v1beta1/account_info/"+e.address, &info); err != nil || status >= 400 || info.Info == nil {
		t.Fatalf("account %s not found (HTTP %d): %v", e.address, status, err)
	}
	accountNumber, _ := strconv.ParseUint(info.Info.AccountNumber, 10, 64)
	sequence, _ := strconv.ParseUint(info.Info.Sequence, 10, 64)
	body := qoresign.Concat(qoresign.LenField(1, qoresign.EncodeAny(msg)), qoresign.StringField(2, "qoreseal go live test"))
	sign := func(gasLimit uint64, version qoresign.SignBytesVersion) ([]byte, error) {
		fee := (gasLimit + 9) / 10 // 0.1 uqor per gas, rounded up
		signed, err := qoresign.SignHybrid(qoresign.SignHybridArgs{
			ChainID: e.chainID, AccountNumber: accountNumber, BodyBytes: body,
			AuthInfoBytes: authInfo(e.classical.PublicKey, sequence, gasLimit, strconv.FormatUint(fee, 10)),
			ClassicalKey:  e.classical, PqKey: &e.pq, SignBytesVersion: version,
		})
		return signed.TxBytes, err
	}
	version, err := e.sign.ResolveSignBytesVersion(ctx, e.chainID)
	if err != nil {
		t.Fatal(err)
	}
	sim, err := e.sign.SimulateTx(ctx, must(sign(600_000, version)), nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.sign.SubmitWithSignBytesFallback(ctx, qsnet.SubmitArgs{
		ChainID: e.chainID, SignBytesVersion: version,
		Sign: func(v qoresign.SignBytesVersion) ([]byte, error) { return sign(sim.SuggestedGasLimit, v) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != 0 {
		why, _ := qoreseal.DescribeKemRegistryError(res.Codespace, res.Code)
		t.Fatalf("broadcast refused: %s %d: %s %s", res.Codespace, res.Code, why, res.Log)
	}
	for i := 0; i < 40; i++ {
		var tx struct {
			TxResponse struct {
				Code   uint32 `json:"code"`
				RawLog string `json:"raw_log"`
			} `json:"tx_response"`
		}
		status, err := liveGet(ctx, e.rest+"/cosmos/tx/v1beta1/txs/"+res.TxHash, &tx)
		if err == nil && status == http.StatusOK {
			if tx.TxResponse.Code != 0 {
				t.Fatalf("transaction %s failed: %s", res.TxHash, tx.TxResponse.RawLog)
			}
			return res.TxHash
		}
		time.Sleep(1500 * time.Millisecond)
	}
	t.Fatalf("transaction %s was not committed", res.TxHash)
	return ""
}

func TestLiveKemRegistry(t *testing.T) {
	env := liveSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// A fresh key every run, so registering always changes the published key.
	keys := must(qoreseal.GenerateSealKeys())

	txhash := env.sendHybrid(ctx, t, must(qoreseal.BuildRegisterKemKeyMessage(env.address, keys.MlkemPublicKey)))
	st, err := env.seal.FetchKemKey(ctx, env.address)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Registered || st.AlgorithmID != qoreseal.AlgorithmMLKEM1024 || qoreseal.ToHex(st.PublicKey) != qoreseal.ToHex(keys.MlkemPublicKey) {
		t.Fatalf("registered key differs: %+v", st.Registered)
	}
	t.Logf("registered at height %d (tx %s)", st.RegisteredHeight, txhash)

	card := must(qoreseal.SignRecipientCard(qoreseal.SignRecipientCardArgs{
		ChainID: env.chainID, Address: env.address, Keys: keys, ClassicalKey: env.classical, PqKey: env.pq,
	}))
	message := []byte("sealed on " + env.chainID + " at " + time.Now().UTC().Format(time.RFC3339))
	for _, mode := range []qoreseal.Mode{qoreseal.ModeHybrid, qoreseal.ModeMlkem} {
		sealed, err := env.seal.SealToAddresses(ctx, network.SealToArgs{
			ChainID: env.chainID, Purpose: "qoreseal-live-test", Mode: mode,
			Recipients: []network.AddressRecipient{{Address: env.address, Card: &card}}, Plaintext: message,
		})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		pt, err := qoreseal.Open(qoreseal.OpenArgs{ChainID: env.chainID, Purpose: "qoreseal-live-test", Envelope: sealed, Keys: keys})
		if err != nil || string(pt) != string(message) {
			t.Fatalf("%s: open: %v", mode, err)
		}
	}

	removeTx := env.sendHybrid(ctx, t, must(qoreseal.BuildRemoveKemKeyMessage(env.address)))
	st, err = env.seal.FetchKemKey(ctx, env.address)
	if err != nil {
		t.Fatal(err)
	}
	if st.Registered {
		t.Fatal("the key is still registered after MsgRemoveKEMKey")
	}
	t.Logf("removed (tx %s)", removeTx)
}
