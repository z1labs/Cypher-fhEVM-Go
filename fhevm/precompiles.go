package fhevm

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel"
)

// Only the TFHEExecutor contract is allowed to call the FheLib precompile.
// Safe calls are exception from above, e.g. fhePubKey and getCiphertext.
var tfheExecutorContractAddress common.Address

func init() {
	addr, found := os.LookupEnv("TFHE_EXECUTOR_CONTRACT_ADDRESS")
	if !found {
		panic("TFHE_EXECUTOR_CONTRACT_ADDRESS not found")
	}
	tfheExecutorContractAddress = common.HexToAddress(addr)
}

func FheLibRequiredGas(environment EVMEnvironment, input []byte) uint64 {
	logger := environment.GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	// first 4 bytes are for the function signature
	signature := binary.BigEndian.Uint32(input[0:4])

	fheLibMethod, found := GetFheLibMethod(signature)
	if !found {
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return 0
	}
	// we remove function signature
	input = input[4:]
	return fheLibMethod.RequiredGas(environment, input)
}

func FheLibRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool) (ret []byte, err error) {
	logger := environment.GetLogger()
	if len(input) < 4 {
		err := errors.New("input must contain at least 4 bytes for method signature")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}
	// first 4 bytes are for the function signature
	signature := binary.BigEndian.Uint32(input[0:4])

	fheLibMethod, found := GetFheLibMethod(signature)
	if !found {
		err := errors.New("precompile method not found")
		logger.Error("fheLib precompile error", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	// Only allow safe methods from any caller. We do that to avoid changing infrastructure.
	if !isSafeFromAnyCaller(fheLibMethod.name) && caller != tfheExecutorContractAddress {
		err := fmt.Errorf("called from address %s which is not the expected TFHEExecutor address %s", caller.Hex(), tfheExecutorContractAddress.Hex())
		logger.Error(err.Error())
		return nil, err
	}

	// remove function signature
	input = input[4:]
	// trace function execution

	if ctx := environment.OtelContext(); ctx != nil {
		_, span := otel.Tracer("fhevm").Start(ctx, fheLibMethod.name)
		ret, err = fheLibMethod.Run(environment, caller, addr, input, readOnly, span)
		if err != nil {
			span.RecordError(err)
		}
		span.End()
	} else {
		ret, err = fheLibMethod.Run(environment, caller, addr, input, readOnly, nil)
	}

	return
}
