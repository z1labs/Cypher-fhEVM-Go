package fhevm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/zama-ai/fhevm-go/fhevm/kms"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const verifyCipertextAbiJson = `
	[
		{
			"name": "verifyCiphertext",
			"type": "function",
			"inputs": [
				{
					"name": "inputHandle",
					"type": "bytes32"
				},
				{
					"name": "callerAddress",
					"type": "address"
				},
				{
					"name": "contractAddress",
					"type": "address"
				},
				{
					"name": "inputProof",
					"type": "bytes"
				},
				{
					"name": "inputType",
					"type": "bytes1"
				}
			],
			"outputs": [
				{
					"name": "",
					"type": "uint256"
				}
			]
		}
	]
`

var verifyCipertextMethod abi.Method

func init() {
	reader := strings.NewReader(verifyCipertextAbiJson)
	verifyCiphertextAbi, err := abi.JSON(reader)
	if err != nil {
		panic(err)
	}

	var ok bool
	verifyCipertextMethod, ok = verifyCiphertextAbi.Methods["verifyCiphertext"]
	if !ok {
		panic("couldn't find the verifyCiphertext method")
	}
}

func parseVerifyCiphertextInput(environment EVMEnvironment, input []byte) ([32]byte, *tfhe.TfheCiphertext, error) {
	unpacked, err := verifyCipertextMethod.Inputs.UnpackValues(input)
	if err != nil {
		return [32]byte{}, nil, err
	} else if len(unpacked) != 5 {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput unexpected unpacked len: %d", len(unpacked))
	}

	// Get handle from input.
	handle, ok := unpacked[0].([32]byte)
	if !ok {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput failed to parse bytes32 inputHandle")
	}

	// Get the ciphertext from the input.
	ciphertextList, ok := unpacked[3].([]byte)
	if !ok || len(ciphertextList) == 0 {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput failed to parse bytes inputProof")
	}

	// Get the type from the input.
	inputTypeByteArray, ok := unpacked[4].([1]byte)
	if !ok {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput failed to parse byte inputType")
	}
	if !tfhe.IsValidFheType(inputTypeByteArray[0]) {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput invalid inputType")
	}
	inputType := tfhe.FheUintType(inputTypeByteArray[0])

	// Get the type from the handle.
	handleIndex := uint8(handle[29])
	handleTypeByte := handle[30]
	if !tfhe.IsValidFheType(handleTypeByte) {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput invalid handleType")
	}
	handleType := tfhe.FheUintType(handleTypeByte)

	// Make sure handle type matches the input type.
	if handleType != inputType {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput handle type (%d) is different from the input type (%d)", handleType, inputType)
	}

	// Make sure hash in the handle is correct.
	ciphertextListHash := crypto.Keccak256Hash(ciphertextList)
	ciphertextListAndIndexHash := crypto.Keccak256Hash(append(ciphertextListHash.Bytes(), handleIndex))
	if !bytes.Equal(ciphertextListAndIndexHash[:29], handle[:29]) {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput input hash doesn't match handle hash")
	}

	var cts []*tfhe.TfheCiphertext
	if environment.FhevmData().expandedInputCiphertexts == nil {
		environment.FhevmData().expandedInputCiphertexts = make(map[common.Hash][]*tfhe.TfheCiphertext)
	}
	if cts, ok = environment.FhevmData().expandedInputCiphertexts[ciphertextListHash]; !ok {
		if inputType == tfhe.FheUint2048 {
			cts, err = tfhe.DeserializeAndExpandCompact2048List(ciphertextList)
		} else {
			cts, err = tfhe.DeserializeAndExpandCompact160List(ciphertextList)
		}
		if err != nil {
			return [32]byte{}, nil, err
		}
	}

	// Extract ciphertext from the list via the handle index.
	if int(handleIndex) >= len(cts) {
		return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput ciphertext index out of range")
	}
	ct := cts[handleIndex]

	// Cast, if needed.
	if inputType == tfhe.FheUint2048 {
		if handleType != tfhe.FheUint2048 {
			return [32]byte{}, nil, fmt.Errorf("parseVerifyCiphertextInput only FheUint2048 allowed in FheUint2048List")
		}
	} else {
		if handleType != ct.Type() {
			ct, err = ct.CastTo(handleType)
			if err != nil {
				return [32]byte{}, nil, err
			}
		}
	}
	environment.FhevmData().expandedInputCiphertexts[ciphertextListHash] = cts
	return handle, ct, nil
}

func verifyCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	logger := environment.GetLogger()

	handle, ct, err := parseVerifyCiphertextInput(environment, input)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	otelDescribeOperandsFheTypes(runSpan, ct.Type())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, ct.Type()), nil
	}

	insertCiphertextToMemory(environment, handle, ct)
	if environment.IsCommitting() {
		//logger.Info("verifyCiphertext success",
		//"ctHash", ct.GetHash().Hex())
	}
	return handle[:], nil
}

func getCiphertextRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()
	if !environment.IsEthCall() {
		msg := "getCiphertext only supported on EthCall"
		logger.Error(msg)
		return nil, errors.New(msg)
	}
	if len(input) != 32 {
		msg := "getCiphertext input len must be 32 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	handle := common.BytesToHash(input)
	ciphertext, _ := loadCiphertext(environment, handle)
	if ciphertext == nil {
		msg := fmt.Sprintf("getCiphertext couldn't find handle %s", handle.Hex())
		logger.Error(msg)
		return make([]byte, 0), errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ciphertext.FheUintType)
	return ciphertext.Serialize(), nil
}

func decryptValue(environment EVMEnvironment, ct *tfhe.TfheCiphertext) (*big.Int, error) {

	logger := environment.GetLogger()
	var fheType kms.FheType
	switch ct.Type() {
	case tfhe.FheBool:
		fheType = kms.FheType_Bool
	case tfhe.FheUint4:
		fheType = kms.FheType_Euint4
	case tfhe.FheUint8:
		fheType = kms.FheType_Euint8
	case tfhe.FheUint16:
		fheType = kms.FheType_Euint16
	case tfhe.FheUint32:
		fheType = kms.FheType_Euint32
	case tfhe.FheUint64:
		fheType = kms.FheType_Euint64
	case tfhe.FheUint160:
		fheType = kms.FheType_Euint160
	}

	// TODO: generate merkle proof for some data
	proof := &kms.Proof{
		Height:              4,
		MerklePatriciaProof: []byte{},
	}

	decryptionRequest := &kms.DecryptionRequest{
		FheType:    fheType,
		Ciphertext: ct.Serialize(),
		Request:    []byte{}, // TODO: change according to the structure of `Request`
		Proof:      proof,
	}

	conn, err := grpc.Dial(kms.KmsEndpointAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errors.New("kms unreachable")
	}
	defer conn.Close()

	ep := kms.NewKmsEndpointClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := ep.Decrypt(ctx, decryptionRequest)
	if err != nil {
		logger.Error("decrypt failed", "err", err)
		return nil, err
	}

	// plaintext is a byte slice
	plaintextBytes := res.Plaintext

	// Variable to hold the resulting big.Int
	plaintextBigInt := new(big.Int).SetBytes(plaintextBytes)

	return plaintextBigInt, nil

}

func castRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "cast Run() input needs to contain a ciphertext and one byte for its type"
		logger.Error(msg, "len", len(input))
		return nil, errors.New(msg)
	}

	ct, _ := loadCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		logger.Error("cast input not verified")
		return nil, errors.New("unverified ciphertext handle")
	}

	if !tfhe.IsValidFheType(input[32]) {
		logger.Error("invalid type to cast to")
		return nil, errors.New("invalid type provided")
	}
	castToType := tfhe.FheUintType(input[32])

	otelDescribeOperandsFheTypes(runSpan, ct.Type(), castToType)

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, castToType), nil
	}

	res, err := ct.CastTo(castToType)
	if err != nil {
		msg := "cast Run() error casting ciphertext to"
		logger.Error(msg, "type", castToType)
		return nil, errors.New(msg)
	}

	resHash := res.GetHash()

	insertCiphertextToMemory(environment, resHash, res)
	if environment.IsCommitting() {
		//logger.Info("cast success",
		//"ctHash", resHash.Hex(),
		//)
	}

	return resHash.Bytes(), nil
}

func fhePubKeyRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(1, len(input))]

	// serialize public key
	pksBytes, err := tfhe.SerializePublicKey()
	if err != nil {
		return nil, err
	}
	// If we have a single byte with the value of 1, make as an EVM array.
	if len(input) == 1 && input[0] == 1 {
		pksBytes = toEVMBytes(pksBytes)
	}
	// pad according to abi specification, first add offset to the dynamic bytes argument
	outputBytes := make([]byte, 32, len(pksBytes)+32)
	outputBytes[31] = 0x20
	outputBytes = append(outputBytes, pksBytes...)
	return padArrayTo32Multiple(outputBytes), nil
}

func trivialEncryptRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(33, len(input))]

	logger := environment.GetLogger()
	if len(input) != 33 {
		msg := "trivialEncrypt input len must be 33 bytes"
		logger.Error(msg, "input", hex.EncodeToString(input), "len", len(input))
		return nil, errors.New(msg)
	}

	valueToEncrypt := *new(big.Int).SetBytes(input[0:32])
	encryptToType := tfhe.FheUintType(input[32])
	otelDescribeOperandsFheTypes(runSpan, encryptToType)

	ct := new(tfhe.TfheCiphertext).TrivialEncrypt(valueToEncrypt, encryptToType)

	ctHash := ct.GetHash()
	insertCiphertextToMemory(environment, ctHash, ct)
	if environment.IsCommitting() {
		// //logger.Info("trivialEncrypt success",
		// 	"ctHash", ctHash.Hex(),
		// 	"valueToEncrypt", valueToEncrypt.Uint64())
	}
	return ctHash.Bytes(), nil
}
