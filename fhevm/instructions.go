package fhevm

import (
	"github.com/ethereum/go-ethereum/common"
	"go.opentelemetry.io/otel"
)

func OpSstore(pc *uint64, env EVMEnvironment, scope ScopeContext) ([]byte, error) {
	// This function is a modified copy from https://github.com/ethereum/go-ethereum
	if otelCtx := env.OtelContext(); otelCtx != nil {
		_, span := otel.Tracer("fhevm").Start(otelCtx, "OpSstore")
		defer span.End()
	}
	if env.IsReadOnly() {
		return nil, ErrWriteProtection
	}
	loc := scope.GetStack().Pop()
	newVal := scope.GetStack().Pop()
	newValHash := common.BytesToHash(newVal.Bytes())
	oldValHash := env.GetState(scope.GetContract().Address(), common.Hash(loc.Bytes32()))
	// If the value is the same or if we are not going to commit, don't do anything to ciphertext storage.
	if newValHash != oldValHash && env.IsCommitting() {
		ct := GetCiphertextFromMemory(env, newValHash)
		if ct != nil {
			persistCiphertext(env, newValHash, ct)
		}
	}
	// Set the SSTORE's value in the actual contract.
	env.SetState(scope.GetContract().Address(), loc.Bytes32(), newValHash)
	return nil, nil
}
