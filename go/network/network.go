// SPDX-License-Identifier: Apache-2.0

// Package network reads QoreSeal recipients from a QoreChain REST endpoint:
// the account's ML-KEM-1024 key from the KEM key registry and, for the hybrid
// mode, its ML-DSA-87 key to verify the recipient card. Everything else in
// QoreSeal works offline.
package network

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
	qsnet "github.com/qorechain/qoresign/go/network"
)

// DefaultTimeout is the HTTP timeout of NewClient.
const DefaultTimeout = 30 * time.Second

// Client talks to one REST endpoint.
type Client struct {
	// REST is the endpoint, e.g. https://api-testnet.qore.host.
	REST string
	// HTTP is the client used for requests; nil uses a client with DefaultTimeout.
	HTTP *http.Client
}

var defaultHTTP = &http.Client{Timeout: DefaultTimeout}

// NewClient returns a Client for rest with a 30-second HTTP timeout.
func NewClient(rest string) *Client {
	return &Client{REST: rest, HTTP: &http.Client{Timeout: DefaultTimeout}}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultHTTP
}

func (c *Client) signClient() *qsnet.Client {
	return &qsnet.Client{REST: c.REST, HTTP: c.httpClient()}
}

func unavailable(code, msg string) error {
	return qoreseal.NewError(code, msg, nil)
}

// KemKeyStatus is the KEM key an account has published, as /qorechain/pqc/v1/kem/{address} reports it.
type KemKeyStatus struct {
	Registered       bool
	Address          string
	AlgorithmID      int
	AlgorithmName    string
	PublicKey        []byte
	RegisteredHeight int64
}

func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// FetchKemKey reads an account's published KEM key. It accepts a qor1 or 0x address.
func (c *Client) FetchKemKey(ctx context.Context, address string) (KemKeyStatus, error) {
	if c == nil || c.REST == "" {
		return KemKeyStatus{}, qoreseal.NewError(qoreseal.CodeInvalidArgument, "a REST endpoint is required", nil)
	}
	path := "/qorechain/pqc/v1/kem/" + url.PathEscape(address)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.REST, "/")+path, nil)
	if err != nil {
		return KemKeyStatus{}, qoreseal.NewError(qoreseal.CodeInvalidArgument, "invalid REST endpoint", nil)
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return KemKeyStatus{}, qoreseal.NewError(qoreseal.CodeNetworkUnavailable, "request to "+path+" failed", map[string]any{"cause": err.Error()})
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return KemKeyStatus{}, unavailable(qoreseal.CodeNetworkUnavailable, "reading "+path+" failed")
	}
	body := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		body = map[string]any{}
		if res.StatusCode < 400 {
			return KemKeyStatus{}, unavailable(qoreseal.CodeNetworkUnavailable, path+" returned a non-JSON body")
		}
	}
	found, hasFound := body["found"].(bool)
	if res.StatusCode == http.StatusNotImplemented || (res.StatusCode == http.StatusNotFound && !hasFound) {
		return KemKeyStatus{}, unavailable(qoreseal.CodeKemRegistryUnavailable,
			"this network does not serve the KEM key registry (it arrives with v3.2.5)")
	}
	if hasFound && !found {
		return KemKeyStatus{}, nil
	}
	key, _ := body["key"].(map[string]any)
	pkStr, _ := key["public_key"].(string)
	if res.StatusCode >= 400 || !found || key == nil || pkStr == "" {
		return KemKeyStatus{}, unavailable(qoreseal.CodeNetworkUnavailable,
			fmt.Sprintf("could not read the KEM key of %s (HTTP %d)", address, res.StatusCode))
	}
	pk, err := decodeBase64(pkStr)
	if err != nil {
		return KemKeyStatus{}, unavailable(qoreseal.CodeNetworkUnavailable, "the KEM key is not base64")
	}
	out := KemKeyStatus{Registered: true, PublicKey: pk}
	out.Address, _ = key["address"].(string)
	out.AlgorithmName, _ = key["algorithm_name"].(string)
	if n, ok := asInt(key["algorithm_id"]); ok {
		out.AlgorithmID = int(n)
	}
	if n, ok := asInt(key["registered_height"]); ok {
		out.RegisteredHeight = n
	}
	return out, nil
}

// FetchMlkemPublicKey returns the account's ML-KEM-1024 key, checked; KEM_KEY_NOT_REGISTERED when there is none.
func (c *Client) FetchMlkemPublicKey(ctx context.Context, address string) ([]byte, error) {
	st, err := c.FetchKemKey(ctx, address)
	if err != nil {
		return nil, err
	}
	if !st.Registered {
		return nil, qoreseal.NewError(qoreseal.CodeKemKeyNotRegistered, address+" has not published a KEM key", nil)
	}
	if st.AlgorithmID != qoreseal.AlgorithmMLKEM1024 {
		return nil, qoreseal.NewError(qoreseal.CodeUnsupportedAlgorithm,
			fmt.Sprintf("%s published a key of algorithm %d", address, st.AlgorithmID), nil)
	}
	if err := qoreseal.ValidateMlkemPublicKey(st.PublicKey); err != nil {
		return nil, err
	}
	return st.PublicKey, nil
}

// ResolveArgs are the inputs of ResolveRecipient.
type ResolveArgs struct {
	ChainID string
	Address string
	// Card is the account's recipient card; required in hybrid mode.
	Card *qoreseal.RecipientCard
	Mode qoreseal.Mode
}

// ResolveRecipient builds the recipient for an address. Hybrid (default)
// needs the account's recipient card, verified against both keys on chain;
// ModeMlkem uses the registered key alone.
func (c *Client) ResolveRecipient(ctx context.Context, args ResolveArgs) (qoreseal.SealRecipient, error) {
	addr, err := qoresign.ParseAddress(args.Address)
	if err != nil {
		return qoreseal.SealRecipient{}, qoreseal.NewError(qoreseal.CodeInvalidArgument, "invalid account address "+strconv.Quote(args.Address), nil)
	}
	address := addr.Bech32
	kem, err := c.FetchMlkemPublicKey(ctx, address)
	if err != nil {
		return qoreseal.SealRecipient{}, err
	}
	switch args.Mode {
	case qoreseal.ModeMlkem:
		return qoreseal.SealRecipient{MlkemPublicKey: kem}, nil
	case "", qoreseal.ModeHybrid:
	default:
		return qoreseal.SealRecipient{}, qoreseal.NewError(qoreseal.CodeInvalidArgument, "unknown mode "+strconv.Quote(string(args.Mode)), nil)
	}
	if args.Card == nil {
		return qoreseal.SealRecipient{}, qoreseal.NewError(qoreseal.CodeRecipientNeedsX25519,
			"hybrid mode needs the recipient card of "+address+"; use ModeMlkem to use the on-chain key alone", nil)
	}
	pq, err := c.signClient().FetchPqKeyStatus(ctx, address)
	if err != nil {
		return qoreseal.SealRecipient{}, qoreseal.NewError(qoreseal.CodeNetworkUnavailable, "could not read the ML-DSA-87 key of "+address, map[string]any{"cause": err.Error()})
	}
	if !pq.Registered {
		return qoreseal.SealRecipient{}, qoreseal.NewError(qoreseal.CodeCardInvalid, address+" has no ML-DSA-87 key on chain", nil)
	}
	return qoreseal.VerifyRecipientCard(qoreseal.VerifyRecipientCardArgs{
		Card: *args.Card, ChainID: args.ChainID, Address: address, PqPublicKey: pq.PublicKey, MlkemPublicKey: kem,
	})
}

// AddressRecipient is a recipient given by address, with its card for the hybrid mode.
type AddressRecipient struct {
	Address string
	Card    *qoreseal.RecipientCard
}

// SealToArgs are the inputs of SealToAddresses.
type SealToArgs struct {
	ChainID    string
	Purpose    string
	Recipients []AddressRecipient
	Plaintext  []byte
	AAD        []byte
	Mode       qoreseal.Mode
	Anonymous  bool
}

// SealToAddresses resolves each recipient on chain, then seals.
func (c *Client) SealToAddresses(ctx context.Context, args SealToArgs) ([]byte, error) {
	recipients := make([]qoreseal.SealRecipient, 0, len(args.Recipients))
	for _, r := range args.Recipients {
		rec, err := c.ResolveRecipient(ctx, ResolveArgs{ChainID: args.ChainID, Address: r.Address, Card: r.Card, Mode: args.Mode})
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, rec)
	}
	return qoreseal.Seal(qoreseal.SealArgs{
		ChainID: args.ChainID, Purpose: args.Purpose, Recipients: recipients,
		Plaintext: args.Plaintext, AAD: args.AAD, Mode: args.Mode, Anonymous: args.Anonymous,
	})
}
