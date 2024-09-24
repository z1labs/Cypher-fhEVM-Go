package fhevm

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

func verifyCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	_, ct, err := parseVerifyCiphertextInput(environment, input)
	if err != nil {
		environment.GetLogger().Error(
			"verifyCiphertext RequiredGas() input parsing failed",
			"err", err)
		return 0
	}
	return environment.FhevmParams().GasCosts.FheVerify[ct.Type()]
}

func getCiphertextRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if len(input) != 32 {
		logger.Error("getCiphertext RequiredGas() input len must be 32 bytes",
			"input", hex.EncodeToString(input), "len", len(input))
		return 0
	}

	handle := common.BytesToHash(input)
	metadata := loadCiphertextMetadata(environment, handle)
	if metadata == nil {
		return GetNonExistentCiphertextGas
	}
	return environment.FhevmParams().GasCosts.FheGetCiphertext[metadata.fheUintType]
}

func castRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error(
			"cast RequiredGas() input needs to contain a ciphertext and one byte for its type",
			"len", len(input))
		return 0
	}

	ct, loadGas := loadCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("cast RequiredGas() input doesn't point to verified ciphertext", "input", hex.EncodeToString(input))
		return loadGas
	}
	return environment.FhevmParams().GasCosts.FheCast + loadGas
}

func fhePubKeyRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	return environment.FhevmParams().GasCosts.FhePubKey
}

func trivialEncryptRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		logger.Error("trivialEncrypt RequiredGas() input len must be 33 bytes", "input", hex.EncodeToString(input), "len", len(input))
		return 0
	}
	encryptToType := tfhe.FheUintType(input[32])
	return environment.FhevmParams().GasCosts.FheTrivialEncrypt[encryptToType]
}
