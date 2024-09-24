package fhevm

// List of EVM execution errors needed by the fhEVM
var (
	ErrOutOfGas                    error
	ErrCodeStoreOutOfGas           error
	ErrDepth                       error
	ErrInsufficientBalance         error
	ErrContractAddressCollision    error
	ErrExecutionReverted           error
	ErrMaxInitCodeSizeExceeded     error
	ErrMaxCodeSizeExceeded         error
	ErrInvalidJump                 error
	ErrWriteProtection             error
	ErrReturnDataOutOfBounds       error
	ErrGasUintOverflow             error
	ErrInvalidCode                 error
	ErrNonceUintOverflow           error
	ErrAddrProhibited              error
	ErrInvalidCoinbase             error
	ErrSenderAddressNotAllowListed error
)

// Register package errors with other custom errors.
//
// This is useful in cases where returned errors need to be recognized by the framework
// using fhevm-go, without much code changes in the framework.
func RegisterErrors(
	outOfGasError error,
	codeStoreOutOfGasError error,
	depthError error,
	insufficientBalanceError error,
	contractAddressCollisionError error,
	executionRevertedError error,
	maxInitCodeSizeExceededError error,
	maxCodeSizeExceededError error,
	invalidJumpError error,
	writeProtectionError error,
	returnDataOutOfBoundsError error,
	gasUintOverflowError error,
	invalidCodeError error,
	nonceUintOverflowError error,
	addrProhibitedError error,
	invalidCoinbaseError error,
	senderAddressNotAllowListedError error) {
	ErrOutOfGas = outOfGasError
	ErrCodeStoreOutOfGas = codeStoreOutOfGasError
	ErrDepth = depthError
	ErrInsufficientBalance = insufficientBalanceError
	ErrContractAddressCollision = contractAddressCollisionError
	ErrExecutionReverted = executionRevertedError
	ErrMaxInitCodeSizeExceeded = maxInitCodeSizeExceededError
	ErrMaxCodeSizeExceeded = maxCodeSizeExceededError
	ErrInvalidJump = invalidJumpError
	ErrWriteProtection = writeProtectionError
	ErrReturnDataOutOfBounds = returnDataOutOfBoundsError
	ErrGasUintOverflow = gasUintOverflowError
	ErrInvalidCode = invalidCodeError
	ErrNonceUintOverflow = nonceUintOverflowError
	ErrAddrProhibited = addrProhibitedError
	ErrInvalidCoinbase = invalidCoinbaseError
	ErrSenderAddressNotAllowListed = senderAddressNotAllowListedError
}
