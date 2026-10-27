// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	qoresign "github.com/qorechain/qoresign/go"
)

// Type URLs of the chain's KEM key registry messages (qorechain.pqc.v1).
const (
	MsgRegisterKemKeyTypeURL = "/qorechain.pqc.v1.MsgRegisterKEMKey"
	MsgRemoveKemKeyTypeURL   = "/qorechain.pqc.v1.MsgRemoveKEMKey"
)

func kemSender(address string) (string, error) {
	a, err := qoresign.ParseAddress(address)
	if err != nil {
		return "", errorf(CodeInvalidArgument, "invalid account address %q", address)
	}
	return a.Bech32, nil
}

// BuildRegisterKemKeyMessage builds MsgRegisterKEMKey { sender, algorithm_id: 2, public_key }.
// Sign the transaction that carries it hybrid (qoresign.SignHybrid). Registering again replaces the key.
func BuildRegisterKemKeyMessage(sender string, mlkemPublicKey []byte) (qoresign.Any, error) {
	if err := ValidateMlkemPublicKey(mlkemPublicKey); err != nil {
		return qoresign.Any{}, err
	}
	s, err := kemSender(sender)
	if err != nil {
		return qoresign.Any{}, err
	}
	value := qoresign.Concat(
		qoresign.StringField(1, s),
		qoresign.VarintField(2, AlgorithmMLKEM1024),
		qoresign.LenField(3, mlkemPublicKey),
	)
	return qoresign.Any{TypeURL: MsgRegisterKemKeyTypeURL, Value: value}, nil
}

// BuildRemoveKemKeyMessage builds MsgRemoveKEMKey { sender }.
func BuildRemoveKemKeyMessage(sender string) (qoresign.Any, error) {
	s, err := kemSender(sender)
	if err != nil {
		return qoresign.Any{}, err
	}
	return qoresign.Any{TypeURL: MsgRemoveKemKeyTypeURL, Value: qoresign.StringField(1, s)}, nil
}

// KemRegistryErrors are the errors of the KEM key registry (codespace "pqc").
var KemRegistryErrors = map[uint32]string{
	250: "the KEM key registry is not enabled on this chain yet",
	251: "invalid KEM public key",
	252: "no KEM key published for this account",
	253: "this KEM key is already published for this account",
	254: "publishing a KEM key needs a registered post-quantum signature key",
}

// DescribeKemRegistryError explains a refusal of a registry transaction; ok is false when it is not one.
func DescribeKemRegistryError(codespace string, code uint32) (string, bool) {
	if codespace != "pqc" {
		return "", false
	}
	s, ok := KemRegistryErrors[code]
	return s, ok
}
