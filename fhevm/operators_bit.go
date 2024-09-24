package fhevm

import (
	"encoding/hex"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel/trace"
)

func fheShlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShl can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheShl failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheShl operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Shl(rhs)
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheShl success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShl scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarShl(rhs)
		if err != nil {
			logger.Error("fheShl failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheShl scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheShrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheShr failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheShr operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Shr(rhs)
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheShr success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheShr scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarShr(rhs)
		if err != nil {
			logger.Error("fheShr failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheShr scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRotlRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheShl can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheShl failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheShl operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Rotl(rhs)
		if err != nil {
			logger.Error("fheRotl failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheRotl success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheRotl scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarRotl(rhs)
		if err != nil {
			logger.Error("fheRotl failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheRotl scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheRotrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheRotr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if !isScalar {
		lhs, rhs, _, err := load2Ciphertexts(environment, input)
		if err != nil {
			logger.Error("fheRotr failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))
		if lhs.Type() != rhs.Type() {
			msg := "fheRotr operand type mismatch"
			logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
			return nil, errors.New(msg)
		}

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.Rotr(rhs)
		if err != nil {
			logger.Error("fheRotr failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheRotr success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
		return resultHash[:], nil

	} else {
		lhs, rhs, _, err := getScalarOperands(environment, input)
		if err != nil {
			logger.Error("fheRotr scalar failed to load inputs", "err", err, "input", hex.EncodeToString(input))
			return nil, err
		}
		otelDescribeOperands(runSpan, encryptedOperand(*lhs), plainOperand(*rhs))

		// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
		if !environment.IsCommitting() && !environment.IsEthCall() {
			return insertRandomCiphertext(environment, lhs.Type()), nil
		}

		result, err := lhs.ScalarRotr(rhs)
		if err != nil {
			logger.Error("fheRotr failed", "err", err)
			return nil, err
		}
		resultHash := result.GetHash()
		insertCiphertextToMemory(environment, resultHash, result)

		//logger.Info("fheRotr scalar success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.Uint64(), "result", resultHash.Hex())
		return resultHash[:], nil
	}
}

func fheNegRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()

	if len(input) != 32 {
		msg := "fheMax input needs to contain one 256-bit sized value"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)

	}

	ct, _ := loadCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNeg failed to load input"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.Type())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, ct.Type()), nil
	}

	result, err := ct.Neg()
	if err != nil {
		logger.Error("fheNeg failed", "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)

	//logger.Info("fheNeg success", "ct", ct.GetHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheNotRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(32, len(input))]

	logger := environment.GetLogger()

	if len(input) != 32 {
		msg := "fheMax input needs to contain one 256-bit sized value"
		logger.Error(msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)

	}

	ct, _ := loadCiphertext(environment, common.BytesToHash(input[0:32]))
	if ct == nil {
		msg := "fheNot failed to load input"
		logger.Error(msg, msg, "input", hex.EncodeToString(input))
		return nil, errors.New(msg)
	}
	otelDescribeOperandsFheTypes(runSpan, ct.Type())

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, ct.Type()), nil
	}

	result, err := ct.Not()
	if err != nil {
		logger.Error("fheNot failed", "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)

	//logger.Info("fheNot success", "ct", ct.GetHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitAndRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitAnd can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitAnd scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, _, err := load2Ciphertexts(environment, input)
	if err != nil {
		logger.Error("fheBitAnd failed to load inputs", "err", err)
		return nil, err
	}
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))

	if lhs.Type() != rhs.Type() {
		msg := "fheBitAnd operand type mismatch"
		logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, lhs.Type()), nil
	}

	result, err := lhs.Bitand(rhs)
	if err != nil {
		logger.Error("fheBitAnd failed", "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)

	//logger.Info("fheBitAnd success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitOrRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitOr can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitOr scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, _, err := load2Ciphertexts(environment, input)
	if err != nil {
		logger.Error("fheBitOr failed to load inputs", "err", err)
		return nil, err
	}
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))

	if lhs.Type() != rhs.Type() {
		msg := "fheBitOr operand type mismatch"
		logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, lhs.Type()), nil
	}

	result, err := lhs.Bitor(rhs)
	if err != nil {
		logger.Error("fheBitOr failed", "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)

	//logger.Info("fheBitOr success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}

func fheBitXorRun(environment EVMEnvironment, caller common.Address, addr common.Address, input []byte, readOnly bool, runSpan trace.Span) ([]byte, error) {
	input = input[:minInt(65, len(input))]

	logger := environment.GetLogger()

	isScalar, err := isScalarOp(input)
	if err != nil {
		logger.Error("fheBitXor can not detect if operator is meant to be scalar", "err", err, "input", hex.EncodeToString(input))
		return nil, err
	}

	if isScalar {
		msg := "fheBitXor scalar op not supported"
		logger.Error(msg)
		return nil, errors.New(msg)
	}

	lhs, rhs, _, err := load2Ciphertexts(environment, input)
	if err != nil {
		logger.Error("fheBitXor failed to load inputs", "err", err)
		return nil, err
	}
	otelDescribeOperands(runSpan, encryptedOperand(*lhs), encryptedOperand(*rhs))

	if lhs.Type() != rhs.Type() {
		msg := "fheBitXor operand type mismatch"
		logger.Error(msg, "lhs", lhs.Type(), "rhs", rhs.Type())
		return nil, errors.New(msg)
	}

	// If we are doing gas estimation, skip execution and insert a random ciphertext as a result.
	if !environment.IsCommitting() && !environment.IsEthCall() {
		return insertRandomCiphertext(environment, lhs.Type()), nil
	}

	result, err := lhs.Bitxor(rhs)
	if err != nil {
		logger.Error("fheBitXor failed", "err", err)
		return nil, err
	}
	resultHash := result.GetHash()
	insertCiphertextToMemory(environment, resultHash, result)

	//logger.Info("fheBitXor success", "lhs", lhs.GetHash().Hex(), "rhs", rhs.GetHash().Hex(), "result", resultHash.Hex())
	return resultHash[:], nil
}
