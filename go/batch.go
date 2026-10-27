// SPDX-License-Identifier: Apache-2.0

package qoreseal

import (
	"crypto/sha3"
)

var batchMagic = []byte("QSBT")

const (
	batchVersion     = 1
	commitSaltLength = 32
)

// SealBatchArgs are the inputs of SealBatch.
type SealBatchArgs struct {
	EpochKey EpochKey
	// Context names the batch stream, for example the rollup id (same characters as a purpose).
	Context    string
	BatchIndex uint64
	Data       []byte
}

// SealedBatch is an encrypted batch with its commitments.
type SealedBatch struct {
	// Blob is the encrypted batch, to publish (for example as a data-availability blob).
	Blob       []byte
	Epoch      uint64
	BatchIndex uint64
	// CiphertextCommitment is SHA3-256 of the blob.
	CiphertextCommitment []byte
	// PlaintextCommitment is the salted SHA3-256 of the data; members can recompute it after decrypting.
	PlaintextCommitment []byte
}

// OpenedBatch is a decrypted batch.
type OpenedBatch struct {
	SealedBatch
	Context string
	Data    []byte
}

// BatchHeader is the header of a batch blob.
type BatchHeader struct {
	Epoch        uint64
	BatchIndex   uint64
	Context      string
	Nonce        []byte
	HeaderLength int
}

// BatchSize is the size of a batch blob: 83 + context length + data length.
func BatchSize(contextLength, dataLength int) int {
	return 35 + contextLength + commitSaltLength + dataLength + tagLength
}

// BatchPlaintextCommitment is SHA3-256("qorechain-qoreseal-batch-v1" || commitSalt || data).
func BatchPlaintextCommitment(commitSalt, data []byte) []byte {
	h := sha3.Sum256(concat([]byte(BatchCommitmentLabel), commitSalt, data))
	return h[:]
}

func sealBatchWith(args SealBatchArgs, ent entropy) (SealedBatch, error) {
	if err := checkPurpose(args.Context, "context"); err != nil {
		return SealedBatch{}, err
	}
	if args.EpochKey.Epoch == 0 {
		return SealedBatch{}, errorf(CodeInvalidArgument, "epochs start at 1")
	}
	if len(args.EpochKey.Key) != dataKeyLength {
		return SealedBatch{}, errorf(CodeInvalidArgument, "epoch key must be 32 bytes")
	}
	nonce, err := ent.take(nonceLength)
	if err != nil {
		return SealedBatch{}, err
	}
	salt, err := ent.take(commitSaltLength)
	if err != nil {
		return SealedBatch{}, err
	}
	ctx := []byte(args.Context)
	header := concat(batchMagic, []byte{batchVersion, aeadAes256Gcm}, u64(args.EpochKey.Epoch), u64(args.BatchIndex), []byte{byte(len(ctx))}, ctx, nonce)
	ct := gcmFor(args.EpochKey.Key).Seal(nil, nonce, concat(salt, args.Data), header)
	blob := concat(header, ct)
	h := sha3.Sum256(blob)
	return SealedBatch{
		Blob: blob, Epoch: args.EpochKey.Epoch, BatchIndex: args.BatchIndex,
		CiphertextCommitment: h[:], PlaintextCommitment: BatchPlaintextCommitment(salt, args.Data),
	}, nil
}

// SealBatch encrypts batch data under an epoch key (spec section 8.2).
func SealBatch(args SealBatchArgs) (SealedBatch, error) {
	return sealBatchWith(args, systemEntropy{})
}

// sealBatchWithEntropy is SealBatch with its nonce (12) and commitment salt (32) given. For test vectors only.
func sealBatchWithEntropy(args SealBatchArgs, ent []byte) (SealedBatch, error) {
	s := &streamEntropy{b: ent}
	out, err := sealBatchWith(args, s)
	if err != nil {
		return SealedBatch{}, err
	}
	if err := s.done(); err != nil {
		return SealedBatch{}, err
	}
	return out, nil
}

// ParseBatchHeader reads a batch blob's header without decrypting it.
func ParseBatchHeader(blob []byte) (BatchHeader, error) {
	if len(blob) < 6 || !equalBytes(blob[:4], batchMagic) {
		return BatchHeader{}, errorf(CodeMalformedBatch, "not a QoreSeal batch")
	}
	if blob[4] != batchVersion {
		return BatchHeader{}, errorf(CodeUnsupportedVersion, "unsupported batch version %d", blob[4])
	}
	if blob[5] != aeadAes256Gcm {
		return BatchHeader{}, errorf(CodeUnsupportedAlgorithm, "unsupported batch cipher")
	}
	if len(blob) < 23 {
		return BatchHeader{}, errorf(CodeMalformedBatch, "truncated batch")
	}
	c := int(blob[22])
	headerLength := 23 + c + nonceLength
	if c == 0 || c > 128 || len(blob) < headerLength+commitSaltLength+tagLength {
		return BatchHeader{}, errorf(CodeMalformedBatch, "truncated batch")
	}
	context := string(blob[23 : 23+c])
	if checkPurpose(context, "context") != nil {
		return BatchHeader{}, errorf(CodeMalformedBatch, "invalid batch context")
	}
	return BatchHeader{
		Epoch: readU64(blob[6:14]), BatchIndex: readU64(blob[14:22]), Context: context,
		Nonce: clone(blob[23+c : headerLength]), HeaderLength: headerLength,
	}, nil
}

// EpochKeySource returns the key of an epoch, if known. EpochKeyManager.KeyFor is one.
type EpochKeySource func(epoch uint64) ([]byte, bool)

// KeysFromList is an EpochKeySource over a list of epoch keys.
func KeysFromList(keys []EpochKey) EpochKeySource {
	return func(epoch uint64) ([]byte, bool) {
		for _, k := range keys {
			if k.Epoch == epoch {
				return k.Key, true
			}
		}
		return nil, false
	}
}

// OpenBatch decrypts a batch blob with the key of its epoch.
func OpenBatch(blob []byte, keys EpochKeySource) (OpenedBatch, error) {
	h, err := ParseBatchHeader(blob)
	if err != nil {
		return OpenedBatch{}, err
	}
	key, ok := keys(h.Epoch)
	if !ok || key == nil {
		return OpenedBatch{}, errorf(CodeUnknownEpoch, "no key for epoch %d", h.Epoch)
	}
	if len(key) != dataKeyLength {
		return OpenedBatch{}, errorf(CodeInvalidArgument, "epoch key must be 32 bytes")
	}
	inner, err := gcmFor(key).Open(nil, h.Nonce, blob[h.HeaderLength:], blob[:h.HeaderLength])
	if err != nil {
		return OpenedBatch{}, errorf(CodeDecryptionFailed, "the batch does not authenticate under the key of its epoch")
	}
	salt, data := inner[:commitSaltLength], clone(inner[commitSaltLength:])
	if data == nil {
		data = []byte{}
	}
	sum := sha3.Sum256(blob)
	return OpenedBatch{
		SealedBatch: SealedBatch{
			Blob: clone(blob), Epoch: h.Epoch, BatchIndex: h.BatchIndex,
			CiphertextCommitment: sum[:], PlaintextCommitment: BatchPlaintextCommitment(salt, data),
		},
		Context: h.Context,
		Data:    data,
	}, nil
}

// BatchKeys is what a PrivateBatchCodec needs; *EpochKeyManager implements it.
type BatchKeys interface {
	CurrentKey() EpochKey
	KeyFor(epoch uint64) ([]byte, bool)
}

// PrivateBatchCodec is SealBatch and OpenBatch bound to one context and key source.
type PrivateBatchCodec struct {
	Context string
	Keys    BatchKeys
}

// NewPrivateBatchCodec checks the context and returns a codec.
func NewPrivateBatchCodec(context string, keys BatchKeys) (*PrivateBatchCodec, error) {
	if err := checkPurpose(context, "context"); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errorf(CodeInvalidArgument, "a key source is required")
	}
	return &PrivateBatchCodec{Context: context, Keys: keys}, nil
}

// Seal encrypts under the current epoch key.
func (c *PrivateBatchCodec) Seal(batchIndex uint64, data []byte) (SealedBatch, error) {
	return SealBatch(SealBatchArgs{EpochKey: c.Keys.CurrentKey(), Context: c.Context, BatchIndex: batchIndex, Data: data})
}

// Open decrypts a blob of this codec's context.
func (c *PrivateBatchCodec) Open(blob []byte) (OpenedBatch, error) {
	out, err := OpenBatch(blob, c.Keys.KeyFor)
	if err != nil {
		return OpenedBatch{}, err
	}
	if out.Context != c.Context {
		return OpenedBatch{}, errorf(CodeDecryptionFailed, "the batch belongs to %s", out.Context)
	}
	return out, nil
}
