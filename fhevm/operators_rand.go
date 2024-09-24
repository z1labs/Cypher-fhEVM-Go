package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	fhevm_crypto "github.com/zama-ai/fhevm-go/fhevm/crypto"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/chacha20"
)

var globalRngSeed []byte

var rngNonceKey [32]byte = uint256.NewInt(0).Bytes32()

func init() {
	if chacha20.NonceSizeX != 24 {
		panic("expected 24 bytes for NonceSizeX")
	}

	// TODO: Since the current implementation is not FHE-based and, hence, not private,
	// we just initialize the global seed with non-random public data. We will change
	// that once the FHE version is available.
	globalRngSeed = make([]byte, chacha20.KeySize)
	for i := range globalRngSeed {
		globalRngSeed[i] = byte(1 + i)
	}
}

// Applies the upperBound (if set) to the rand value and returns the result.
// bitsInRand is the amount of random bits that are contained in rand.
// bitsInRand and upperBound must be powers of 2.
func applyUpperBound(rand uint64, bitsInRand int, upperBound *uint64) uint64 {
	if upperBound == nil {
		return rand
	} else if *upperBound == 0 {
		panic("sliceRandom called with upperBound of 0")
	}
	// Len64() returns the amount of bits needed to represent upperBound. Subtract 1 to get the
	// amount of bits requested by the given upperBound as we want to return a value in the [0, upperBound) range.
	// Note that upperBound is assumed to be a power of 2.
	//
	// For example, if upperBound = 128, then bits = 8 - 1 = 7 random bits to be returned.
	// To get that amount of random bits from rand, subtract bits from bitsInRand, i.e.
	// shift = 32 - 7 = 25. Shifting rand 25 positions would leave 7 of its random bits.
	bits := bits.Len64(*upperBound) - 1
	shift := bitsInRand - bits
	// If the shift ends up negative or 0, just return rand without any shifts.
	if shift <= 0 {
		return rand
	}
	return rand >> shift
}

func generateRandom(environment EVMEnvironment, caller common.Address, resultType tfhe.FheUintType, upperBound *uint64) ([]byte, error) {
	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() {
		return insertRandomCiphertext(environment, resultType), nil
	}

	// Get the RNG nonce.
	protectedStorage := fhevm_crypto.CreateProtectedStorageContractAddress(caller)
	currentRngNonceBytes := environment.GetState(protectedStorage, rngNonceKey).Bytes()

	// Increment the RNG nonce by 1.
	nextRngNonce := uint256.NewInt(0).SetBytes(currentRngNonceBytes)
	nextRngNonce = nextRngNonce.AddUint64(nextRngNonce, 1)
	environment.SetState(protectedStorage, rngNonceKey, nextRngNonce.Bytes32())

	// Compute the seed and use it to create a new cipher.
	hasher := crypto.NewKeccakState()
	hasher.Write(globalRngSeed)
	hasher.Write(caller.Bytes())
	seed := common.Hash{}
	_, err := hasher.Read(seed[:])
	if err != nil {
		return nil, err
	}
	// The RNG nonce bytes are of size chacha20.NonceSizeX, which is assumed to be 24 bytes (see init() above).
	// Since uint256.Int.z[0] is the least significant byte and since uint256.Int.Bytes32() serializes
	// in order of z[3], z[2], z[1], z[0], we want to essentially ignore the first byte, i.e. z[3], because
	// it will always be 0 as the nonce size is 24.
	cipher, err := chacha20.NewUnauthenticatedCipher(seed.Bytes(), currentRngNonceBytes[32-chacha20.NonceSizeX:32])
	if err != nil {
		return nil, err
	}

	// XOR a byte array of 0s with the stream from the cipher and receive the result in the same array.
	// Apply upperBound, if set.
	var randUint uint64
	switch resultType {
	case tfhe.FheUint4:
		randBytes := make([]byte, 1)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(randBytes[0])
		randUint = uint64(applyUpperBound(randUint, 4, upperBound))
	case tfhe.FheUint8:
		randBytes := make([]byte, 1)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(randBytes[0])
		randUint = uint64(applyUpperBound(randUint, 8, upperBound))
	case tfhe.FheUint16:
		randBytes := make([]byte, 2)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(binary.BigEndian.Uint16(randBytes))
		randUint = uint64(applyUpperBound(randUint, 16, upperBound))
	case tfhe.FheUint32:
		randBytes := make([]byte, 4)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(binary.BigEndian.Uint32(randBytes))
		randUint = uint64(applyUpperBound(randUint, 32, upperBound))
	case tfhe.FheUint64:
		randBytes := make([]byte, 8)
		cipher.XORKeyStream(randBytes, randBytes)
		randUint = uint64(binary.BigEndian.Uint64(randBytes))
		randUint = uint64(applyUpperBound(randUint, 64, upperBound))
	default:
		return nil, fmt.Errorf("generateRandom() invalid type requested: %d", resultType)
	}

	// Trivially encrypt the random integer.
	randCt := new(tfhe.TfheCiphertext)
	randBigInt := big.NewInt(0)
	randBigInt.SetUint64(randUint)
	randCt.TrivialEncrypt(*randBigInt, resultType)
	ctHash := randCt.GetHash()
	insertCiphertextToMemory(environment, ctHash, randCt)
	return ctHash[:], nil
}

func fheRandRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(1, len(input))]

	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRand cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 1 || !tfhe.IsValidFheType(input[0]) {
		msg := "fheRand input len must be at least 1 byte and be a valid FheUint type"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}
	resultType := tfhe.FheUintType(input[0])
	otelDescribeOperandsFheTypes(runSpan, resultType)
	var noUpperBound *uint64 = nil
	return generateRandom(environment, caller, resultType, noUpperBound)
}

func fheRandBoundedRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if environment.IsEthCall() {
		msg := "fheRandBoundedRun cannot be called via EthCall, because it needs to mutate internal state"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	randType, bound, err := parseRandUpperBoundInput(input)
	if err != nil {
		msg := "fheRandBounded bound error"
		logger.Error(msg, "input", hex.EncodeToString(input), "err", err)
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, randType)
	bound64 := bound.Uint64()
	return generateRandom(environment, caller, randType, &bound64)
}
