package fhevm

import (
	"log/slog"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"github.com/zama-ai/fhevm-go/fhevm/tfhe"
)

var protectedStorageAddrCallerAddr common.Address
var defaultProtectedStorageAddrCallerAddr = []byte{93}

// Set the addr to be used as caller when creating protected storage contracts
func SetProtectedStorageAddrCallerAddr(addr []byte) {
	protectedStorageAddrCallerAddr = common.BytesToAddress(addr)
}

func init() {
	SetProtectedStorageAddrCallerAddr(defaultProtectedStorageAddrCallerAddr)
}

// A Logger interface for the EVM.
type Logger interface {
	Debug(msg string, keyvals ...interface{})
	Info(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
}

// A default Logger implementation that logs to stdout.
type DefaultLogger struct {
	slogger *slog.Logger
}

func NewDefaultLogger() Logger {
	logger := &DefaultLogger{}
	logger.slogger = slog.Default().With("module", "fhevm-go")
	return logger
}

func (l *DefaultLogger) Debug(msg string, keyvals ...interface{}) {
	l.slogger.Debug(msg, keyvals...)
}

func (l *DefaultLogger) Info(msg string, keyvals ...interface{}) {
	l.slogger.Info(msg, keyvals...)
}

func (l *DefaultLogger) Error(msg string, keyvals ...interface{}) {
	l.slogger.Error(msg, keyvals...)
}

func insertRandomCiphertext(environment EVMEnvironment, t tfhe.FheUintType) []byte {
	nextCtHash := &environment.FhevmData().nextCiphertextHashOnGasEst
	ctHashBytes := crypto.Keccak256(nextCtHash.Bytes())
	handle := common.BytesToHash(ctHashBytes)
	ct := new(tfhe.TfheCiphertext)
	ct.FheUintType = t
	ct.Hash = &handle
	insertCiphertextToMemory(environment, handle, ct)
	temp := nextCtHash.Clone()
	nextCtHash.Add(temp, uint256.NewInt(1))
	return ct.GetHash().Bytes()
}

func InitFhevm(accessibleState EVMEnvironment) {}
