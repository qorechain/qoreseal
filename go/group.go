// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"sort"
	"sync"
)

// EpochKeyPayloadLength is the size of the payload that carries an epoch key inside an envelope.
const EpochKeyPayloadLength = 45

var epochKeyMagic = []byte("QSEK")

const epochKeyVersion = 1

// EpochKey is an epoch number (from 1) and its 32-byte key.
type EpochKey struct {
	Epoch uint64
	Key   []byte
}

// EncodeEpochKey returns the 45-byte payload "QSEK" || 0x01 || epoch || key (spec section 8.1).
func EncodeEpochKey(k EpochKey) ([]byte, error) {
	if k.Epoch == 0 {
		return nil, errorf(CodeInvalidArgument, "epochs start at 1")
	}
	if len(k.Key) != dataKeyLength {
		return nil, errorf(CodeInvalidArgument, "epoch key must be 32 bytes")
	}
	return concat(epochKeyMagic, []byte{epochKeyVersion}, u64(k.Epoch), k.Key), nil
}

// DecodeEpochKey parses an epoch key payload.
func DecodeEpochKey(p []byte) (EpochKey, error) {
	if len(p) != EpochKeyPayloadLength || !equalBytes(p[:4], epochKeyMagic) {
		return EpochKey{}, errorf(CodeMalformedEnvelope, "the envelope does not carry an epoch key")
	}
	if p[4] != epochKeyVersion {
		return EpochKey{}, errorf(CodeUnsupportedVersion, "unsupported epoch key version %d", p[4])
	}
	epoch := readU64(p[5:13])
	if epoch == 0 {
		return EpochKey{}, errorf(CodeMalformedEnvelope, "epoch 0 is not valid")
	}
	return EpochKey{Epoch: epoch, Key: clone(p[13:45])}, nil
}

// SealEpochKey seals an epoch key to the members of a group.
func SealEpochKey(chainID, purpose string, k EpochKey, recipients []SealRecipient, mode Mode) ([]byte, error) {
	payload, err := EncodeEpochKey(k)
	if err != nil {
		return nil, err
	}
	return Seal(SealArgs{ChainID: chainID, Purpose: purpose, Recipients: recipients, Plaintext: payload, Mode: mode})
}

// OpenEpochKey opens an epoch key sealed with SealEpochKey or by an EpochKeyManager.
func OpenEpochKey(chainID, purpose string, envelope []byte, keys SealKeyPair) (EpochKey, error) {
	p, err := Open(OpenArgs{ChainID: chainID, Purpose: purpose, Envelope: envelope, Keys: keys})
	if err != nil {
		return EpochKey{}, err
	}
	return DecodeEpochKey(p)
}

// Member is a group member: an id of your choice and its recipient keys.
type Member struct {
	ID        string
	Recipient SealRecipient
}

// EpochRotation is what a membership change produced.
type EpochRotation struct {
	Epoch uint64
	// Envelope carries the new epoch key for the members; nil when the group has no members left.
	Envelope []byte
	Members  []string
}

// EpochKeyManagerOptions configure an EpochKeyManager.
type EpochKeyManagerOptions struct {
	ChainID string
	// Purpose of the epoch key envelopes, for example "epoch-key:my-rollup".
	Purpose string
	Mode    Mode
	Members []Member
	// History restores the keys of earlier epochs, in increasing order; the last one is current.
	History []EpochKey
}

// EpochKeyManager keeps the epoch keys of a group on the operator's side.
// Every membership change starts a new epoch with a fresh random key: removed
// members cannot read later epochs, new members cannot read earlier ones.
// It is safe for concurrent use.
type EpochKeyManager struct {
	chainID string
	purpose string
	mode    Mode
	ent     entropy

	mu      sync.Mutex
	order   []string
	members map[string]SealRecipient
	keys    map[uint64][]byte
	current uint64
}

// NewEpochKeyManager starts a manager at epoch 1 (or at the last epoch of History).
func NewEpochKeyManager(opts EpochKeyManagerOptions) (*EpochKeyManager, error) {
	return newEpochKeyManager(opts, systemEntropy{})
}

func newEpochKeyManager(opts EpochKeyManagerOptions, ent entropy) (*EpochKeyManager, error) {
	if err := checkChainID(opts.ChainID); err != nil {
		return nil, err
	}
	if err := checkPurpose(opts.Purpose, "purpose"); err != nil {
		return nil, err
	}
	mode, _, err := normalizeMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	m := &EpochKeyManager{chainID: opts.ChainID, purpose: opts.Purpose, mode: mode, ent: ent,
		members: map[string]SealRecipient{}, keys: map[uint64][]byte{}}
	for _, mem := range opts.Members {
		if err := m.setMember(mem.ID, mem.Recipient); err != nil {
			return nil, err
		}
	}
	for _, k := range opts.History {
		if len(k.Key) != dataKeyLength {
			return nil, errorf(CodeInvalidArgument, "epoch key must be 32 bytes")
		}
		if k.Epoch <= m.current {
			return nil, errorf(CodeInvalidArgument, "history must be in increasing epoch order")
		}
		m.keys[k.Epoch] = clone(k.Key)
		m.current = k.Epoch
	}
	if m.current == 0 {
		if err := m.newEpoch(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *EpochKeyManager) setMember(id string, r SealRecipient) error {
	if id == "" {
		return errorf(CodeInvalidArgument, "member id must be a non-empty string")
	}
	if err := ValidateMlkemPublicKey(r.MlkemPublicKey); err != nil {
		return err
	}
	if m.mode == ModeHybrid && r.X25519PublicKey == nil {
		return errorf(CodeRecipientNeedsX25519, "member %s has no X25519 key; use ModeMlkem or a recipient card", id)
	}
	if _, ok := m.members[id]; !ok {
		if len(m.members) >= MaxRecipients {
			return errorf(CodeInvalidArgument, "a group has at most %d members", MaxRecipients)
		}
		m.order = append(m.order, id)
	}
	m.members[id] = SealRecipient{MlkemPublicKey: clone(r.MlkemPublicKey), X25519PublicKey: clone(r.X25519PublicKey)}
	return nil
}

func (m *EpochKeyManager) newEpoch() error {
	k, err := m.ent.take(dataKeyLength)
	if err != nil {
		return err
	}
	m.current++
	m.keys[m.current] = k
	return nil
}

// Epoch is the current epoch number.
func (m *EpochKeyManager) Epoch() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// CurrentKey is the current epoch and its key.
func (m *EpochKeyManager) CurrentKey() EpochKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	return EpochKey{Epoch: m.current, Key: clone(m.keys[m.current])}
}

// KeyFor returns the key of an epoch this manager knows.
func (m *EpochKeyManager) KeyFor(epoch uint64) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[epoch]
	return clone(k), ok
}

// ExportKeys returns every epoch key, oldest first. Store it encrypted: it opens every batch of the group.
func (m *EpochKeyManager) ExportKeys() []EpochKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]EpochKey, 0, len(m.keys))
	for e, k := range m.keys {
		out = append(out, EpochKey{Epoch: e, Key: clone(k)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch < out[j].Epoch })
	return out
}

// Members returns the member ids in the order they were added.
func (m *EpochKeyManager) Members() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.order...)
}

func (m *EpochKeyManager) distribution() ([]byte, error) {
	if len(m.order) == 0 {
		return nil, errorf(CodeInvalidArgument, "the group has no members")
	}
	recipients := make([]SealRecipient, 0, len(m.order))
	for _, id := range m.order {
		recipients = append(recipients, m.members[id])
	}
	payload, err := EncodeEpochKey(EpochKey{Epoch: m.current, Key: m.keys[m.current]})
	if err != nil {
		return nil, err
	}
	return sealWith(SealArgs{ChainID: m.chainID, Purpose: m.purpose, Mode: m.mode, Recipients: recipients, Plaintext: payload}, m.ent)
}

// Distribution seals the current epoch key to the current members.
func (m *EpochKeyManager) Distribution() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.distribution()
}

func (m *EpochKeyManager) rotate() (EpochRotation, error) {
	if err := m.newEpoch(); err != nil {
		return EpochRotation{}, err
	}
	out := EpochRotation{Epoch: m.current, Members: append([]string(nil), m.order...)}
	if len(m.order) > 0 {
		env, err := m.distribution()
		if err != nil {
			return EpochRotation{}, err
		}
		out.Envelope = env
	}
	return out, nil
}

// Rotate starts a new epoch without a membership change (for example on a schedule).
func (m *EpochKeyManager) Rotate() (EpochRotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotate()
}

// AddMember adds or replaces a member and starts a new epoch.
func (m *EpochKeyManager) AddMember(id string, r SealRecipient) (EpochRotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.setMember(id, r); err != nil {
		return EpochRotation{}, err
	}
	return m.rotate()
}

// RemoveMember removes a member and starts a new epoch it cannot read.
func (m *EpochKeyManager) RemoveMember(id string) (EpochRotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.members[id]; !ok {
		return EpochRotation{}, errorf(CodeInvalidArgument, "no member %q", id)
	}
	delete(m.members, id)
	for i, x := range m.order {
		if x == id {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	return m.rotate()
}
