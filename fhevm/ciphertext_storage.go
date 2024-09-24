package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var CiphertextStorageAddress = common.BytesToAddress([]byte{94})

func newInt(buf []byte) *uint256.Int {
	i := uint256.NewInt(0)
	return i.SetBytes(buf)
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// Ciphertext metadata is stored in a single 32-byte slot.
// Currently, we only utilize 9 bytes from the slot.
type ciphertextMetadata struct {
	length      uint64
	fheUintType tfhe.FheUintType
}

func (m ciphertextMetadata) serialize() [32]byte {
	u := uint256.NewInt(0)
	u[0] = m.length
	u[1] = uint64(m.fheUintType)
	return u.Bytes32()
}

func (m *ciphertextMetadata) deserialize(buf [32]byte) *ciphertextMetadata {
	u := uint256.NewInt(0)
	u.SetBytes(buf[:])
	m.length = u[0]
	m.fheUintType = tfhe.FheUintType(u[1])
	return m
}

func newCiphertextMetadata(buf [32]byte) *ciphertextMetadata {
	m := ciphertextMetadata{}
	return m.deserialize(buf)
}

func isCiphertextPersisted(env EVMEnvironment, handle common.Hash) bool {
	metadataInt := newInt(env.GetState(CiphertextStorageAddress, handle).Bytes())
	return !metadataInt.IsZero()
}

// Returns the ciphertext metadata for the given handle or nil if it doesn't point to a ciphertext.
func loadCiphertextMetadata(env EVMEnvironment, handle common.Hash) *ciphertextMetadata {
	metadataInt := newInt(env.GetState(CiphertextStorageAddress, handle).Bytes())
	if metadataInt.IsZero() {
		return nil
	}
	return newCiphertextMetadata(metadataInt.Bytes32())
}

// Returns the ciphertext for the given `handle` and the gas needed to laod the ciphertext.
// Returned gas would be zero if already loaded to memory.
// If `handle` doesn't point to a ciphertext or an error occurs, (nil, 0) is returned.
func loadCiphertext(env EVMEnvironment, handle common.Hash) (ct *tfhe.TfheCiphertext, gas uint64) {
	//logger := env.GetLogger()
	ct, loaded := env.FhevmData().loadedCiphertexts[handle]
	if loaded {
		return ct, 0
	}

	metadataInt := newInt(env.GetState(CiphertextStorageAddress, handle).Bytes())
	if metadataInt.IsZero() {
		panic("metadataInt is zero")
		return nil, ColdSloadCostEIP2929
	}
	metadata := newCiphertextMetadata(metadataInt.Bytes32())
	ctBytes := make([]byte, 0)
	left := metadata.length
	idx := newInt(handle.Bytes())
	idx.AddUint64(idx, 1)
	for left > 0 {
		bytes := env.GetState(CiphertextStorageAddress, idx.Bytes32())
		toAppend := minUint64(uint64(len(bytes)), left)
		left -= toAppend
		ctBytes = append(ctBytes, bytes[0:toAppend]...)
		idx.AddUint64(idx, 1)
	}
	ct = new(tfhe.TfheCiphertext)
	err := ct.Deserialize(ctBytes, metadata.fheUintType)
	if err != nil {
		panic(err)
		//logger.Error("failed to deserialize ciphertext from storage", "err", err)
		return nil, ColdSloadCostEIP2929 + DeserializeCiphertextGas
	}
	env.FhevmData().loadedCiphertexts[handle] = ct
	return ct, env.FhevmParams().GasCosts.FheStorageSloadGas[ct.Type()]
}

func insertCiphertextToMemory(env EVMEnvironment, handle common.Hash, ct *tfhe.TfheCiphertext) {
	env.FhevmData().loadedCiphertexts[handle] = ct
}

// Persist the given ciphertext.
func persistCiphertext(env EVMEnvironment, handle common.Hash, ct *tfhe.TfheCiphertext) {
	//logger := env.GetLogger()
	if isCiphertextPersisted(env, handle) {
		// Assuming a handle is a hash of the ciphertext, if metadata is already existing in storage it means the ciphertext is too.
		////logger.Info("ciphertext already persisted to storage", "handle", handle.Hex())
		return
	}

	metadata := ciphertextMetadata{}
	metadata.length = uint64(tfhe.ExpandedFheCiphertextSize[ct.Type()])
	metadata.fheUintType = ct.Type()

	// Persist the metadata in storage.
	env.SetState(CiphertextStorageAddress, handle, metadata.serialize())

	ciphertextSlot := newInt(handle.Bytes())
	ciphertextSlot.AddUint64(ciphertextSlot, 1)
	if env.IsCommitting() {
		// //logger.Info("persisting new ciphertext",
		// 	"handle", hex.EncodeToString(handle.Bytes()),
		// 	"type", metadata.fheUintType,
		// 	"len", metadata.length,
		// 	"ciphertextSlot", hex.EncodeToString(ciphertextSlot.Bytes()))
	}
	ctPart32 := make([]byte, 32)
	partIdx := 0
	ctBytes := ct.Serialize()
	for i, b := range ctBytes {
		if i%32 == 0 && i != 0 {
			env.SetState(CiphertextStorageAddress, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
			ciphertextSlot.AddUint64(ciphertextSlot, 1)
			ctPart32 = make([]byte, 32)
			partIdx = 0
		}
		ctPart32[partIdx] = b
		partIdx++
	}
	if len(ctPart32) != 0 {
		env.SetState(CiphertextStorageAddress, ciphertextSlot.Bytes32(), common.BytesToHash(ctPart32))
	}
}

func GetCiphertextFromMemory(env EVMEnvironment, handle common.Hash) *tfhe.TfheCiphertext {
	ct, found := env.FhevmData().loadedCiphertexts[handle]
	if found {
		return ct
	}
	return nil
}
