# Integration

This document is a guide listing detailed steps to integrate `fhevm-go` into [go-ethereum](https://github.com/ethereum/go-ethereum) or any other implementations that follow the same architecture.

{% hint style="info" %}
This document is based on go-ethereum v1.13.5
{% endhint %}

## Steps

### Step 1: update `core/state_transition.go`

```go
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead, isEIP2028 bool, isEIP3860 bool) (uint64, error)
```

replace the last return with:

```go
return fhevm.TxDataFractionalGas(gas), nil
```

which will impact tests as the returned gas won’t be the same.

### Step 2: update `core/vm/contracts.go`

update the `PrecompiledContract` interface to:

```go
type PrecompileAccessibleState interface {
    Interpreter() *EVMInterpreter
}

type PrecompiledContract interface {
    RequiredGas(accessibleState PrecompileAccessibleState, input []byte) uint64
    Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error)
}
```

#### Update all previous uses of this interface

Add:

```go
common.BytesToAddress([]byte{93}): &fheLib{}
```

to all precompiled contract maps (e.g. `PrecompiledContractsHomestead` )

{% hint style="info" %}
We used 93 as the address of the precompile here, but you can choose any other address as far as client libraries know where to find it.
{% endhint %}

#### Implement the `fheLib` precompile

```go
// fheLib calls into the different precompile functions available in the fhevm
type fheLib struct{}

func (c *fheLib) RequiredGas(accessibleState PrecompileAccessibleState, input []byte) uint64 {
    return fhevm.FheLibRequiredGas(accessibleState.Interpreter().evm.FhevmEnvironment(), input)
}

func (c *fheLib) Run(accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, readOnly bool) ([]byte, error) {
    return fhevm.FheLibRun(accessibleState.Interpreter().evm.FhevmEnvironment(), caller, addr, input, readOnly)
}
```

#### Rewrite `RunPrecompiledContract`

```go
func RunPrecompiledContract(p PrecompiledContract, accessibleState PrecompileAccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64) (ret []byte, remainingGas uint64, err error) {
    gasCost := p.RequiredGas(accessibleState, input)
    if suppliedGas < gasCost {
        return nil, 0, ErrOutOfGas
    }

    suppliedGas -= gasCost
    output, err := p.Run(accessibleState, caller, addr, input, accessibleState.Interpreter().readOnly)

    return output, suppliedGas, err
}
```

### Step 3: update `core/vm/errors.go`

#### Register errors at initialization in `fhevm-go` to be recognized at runtime

```go
func init() {
    fhevm.RegisterErrors(ErrOutOfGas, ErrCodeStoreOutOfGas, ErrDepth, ErrInsufficientBalance,
        ErrContractAddressCollision, ErrExecutionReverted, ErrMaxInitCodeSizeExceeded, ErrMaxCodeSizeExceeded,
        ErrInvalidJump, ErrWriteProtection, ErrReturnDataOutOfBounds, ErrGasUintOverflow, ErrInvalidCode,
        ErrNonceUintOverflow, nil, nil, nil)
}
```

### Step 4: update `core/vm/evm.go`

#### Update `EVM` struct with new fields

```go
fhevmEnvironment FhevmImplementation
isGasEstimation  bool
isEthCall        bool
```

While implementing `fhevmEnvironment` as:

```go
type FhevmImplementation struct {
    interpreter *EVMInterpreter
    data        fhevm.FhevmData
    logger      fhevm.Logger
    params      fhevm.FhevmParams
}
```

#### Update NewEVM

In:

```go
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM
```

- Initialize `isGasEstimation` using `config.IsGasEstimation`
- Initialize `isEthCall` using `config.IsEthCall`
- Initialize `fhevmEnvironment` with `FhevmImplementation{interpreter: nil, logger: fhevm.NewDefaultLogger(), data: fhevm.NewFhevmData(), params: fhevm.DefaultFhevmParams()}`
- After initializing `evm.interpreter` make sure to point `fhevmEnvironment` to it `evm.fhevmEnvironment.interpreter = evm.interpreter` then initialize it `fhevm.InitFhevm(&evm.fhevmEnvironment)`

#### Update RunPrecompiledContract

After changing precompiled contract interface in 2, we have to change usages of:

```go
RunPrecompiledContract(p, input, gas)
```

to:

```go
RunPrecompiledContract(p, evm, caller.Address(), addr, input, gas)
```

#### Update Create() and Create2() functions

Add code to create ciphertext storage:

```go
// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	// Create the ciphertext storage if not already created.
	if evm.StateDB.GetNonce(fhevm.CiphertextStorageAddress) == 0 {
		evm.StateDB.CreateAccount(fhevm.CiphertextStorageAddress)
		evm.StateDB.SetNonce(fhevm.CiphertextStorageAddress, 1)
	}
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	// Create the ciphertext storage if not already created.
	if evm.StateDB.GetNonce(fhevm.CiphertextStorageAddress) == 0 {
		evm.StateDB.CreateAccount(fhevm.CiphertextStorageAddress)
		evm.StateDB.SetNonce(fhevm.CiphertextStorageAddress, 1)
	}
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr, CREATE2)
}
```

#### Implement EVMEnvironment interface

Now implement the `fhevm.EVMEnvironment` interface for `FhevmImplementation`:

```go
func (evm *EVM) FhevmEnvironment() fhevm.EVMEnvironment { return &evm.fhevmEnvironment }

// If you are using OpenTelemetry, you can return a context that the precompiled fhelib will use
// to trace its internal functions. Otherwise, just return nil
func (evm *FhevmImplementation) OtelContext() context.Context {
       return nil
}

func (evm *FhevmImplementation) GetState(addr common.Address, hash common.Hash) common.Hash {
    return evm.interpreter.evm.StateDB.GetState(addr, hash)
}

func (evm *FhevmImplementation) SetState(addr common.Address, hash common.Hash, input common.Hash) {
    evm.interpreter.evm.StateDB.SetState(addr, hash, input)
}

func (evm *FhevmImplementation) GetNonce(addr common.Address) uint64 {
    return evm.interpreter.evm.StateDB.GetNonce(addr)
}

func (evm *FhevmImplementation) AddBalance(addr common.Address, value *big.Int) {
    evm.interpreter.evm.StateDB.AddBalance(addr, value)
}

func (evm *FhevmImplementation) GetBalance(addr common.Address) *big.Int {
    return evm.interpreter.evm.StateDB.GetBalance(addr)
}

func (evm *FhevmImplementation) Suicide(addr common.Address) bool {
    evm.interpreter.evm.StateDB.SelfDestruct(addr)
    return evm.interpreter.evm.StateDB.HasSelfDestructed(addr)
}

func (evm *FhevmImplementation) GetDepth() int {
    return evm.interpreter.evm.depth
}

func (evm *FhevmImplementation) IsCommitting() bool {
    return !evm.interpreter.evm.isGasEstimation
}

func (evm *FhevmImplementation) IsEthCall() bool {
    return evm.interpreter.evm.isEthCall
}

func (evm *FhevmImplementation) IsReadOnly() bool {
    return evm.interpreter.readOnly
}

func (evm *FhevmImplementation) GetLogger() fhevm.Logger {
    return evm.logger
}

func (evm *FhevmImplementation) FhevmData() *fhevm.FhevmData {
    return &evm.data
}

func (evm *FhevmImplementation) FhevmParams() *fhevm.FhevmParams {
    return &evm.params
}

func (evm *FhevmImplementation) CreateContract(caller common.Address, code []byte, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
    return evm.interpreter.evm.create(AccountRef(caller), &codeAndHash{code: code}, gas, value, address, CREATE)
}

func (evm *FhevmImplementation) CreateContract2(caller common.Address, code []byte, codeHash common.Hash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
    return evm.interpreter.evm.create(AccountRef(caller), &codeAndHash{code: code, hash: codeHash}, gas, value, address, CREATE2)
}
```

### Step 5: update `core/vm/instructions.go`

#### Update `opSstore`

Rewrite `opSstore` by a call to their fhevm implementation:

```go
func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
    return fhevm.OpSstore(pc, interpreter.evm.FhevmEnvironment(), scope)
}
```

### Step 6: update `core/vm/interpreter.go`

#### Update `Config` struct with new fields

```go
IsEthCall               bool
IsGasEstimation         bool
```

#### Implements the `GetMemory`, `GetStack` and `GetContract` methods

```go
func (s *ScopeContext) GetMemory() fhevm.Memory {
    return s.Memory
}

func (s *ScopeContext) GetStack() fhevm.Stack {
    return s.Stack
}

func (s *ScopeContext) GetContract() fhevm.Contract {
    return s.Contract
}
```

#### Update `Run` method

In:

```go
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error)
```

### Step 7: update `core/vm/stack.go`

#### Implement the following methods

```go
func (st *Stack) Pop() uint256.Int {
    return st.pop()
}

func (st *Stack) Peek() *uint256.Int {
    return st.peek()
}
```

### Step 8: update `core/vm/operations_acl.go`

#### Implement gas cost for storing a ciphertext

In `func makeGasSStoreFunc(clearingRefund uint64) gasFunc {`

Just before `original := evm.StateDB.GetCommittedState(contract.Address(), x.Bytes32())`, add this block to increase SSTORE gas cost for storing a ciphertext:

```go
ct := fhevm.GetCiphertextFromMemory(evm.FhevmEnvironment(), value)
if ct != nil {
    cost += evm.fhevmEnvironment.params.GasCosts.FheStorageSstoreGas[ct.Type()]
}
```

### Step 9: update `internal/ethapi/api.go`

- Add `isGasEstimation, isEthCall bool` arguments to `func doCall` and pass them in `vm.Config` during EVM creation:

```go
evm, vmError := b.GetEVM(ctx, msg, state, header, &vm.Config{NoBaseFee: true, IsGasEstimation: isGasEstimation, IsEthCall: isEthCall}, &blockCtx)
```

- Add `isGasEstimation, isEthCall bool` arguments to `func DoCall` and forward them in the call to `doCall`
- Update usages of `doCall` and `DoCall` by simply setting `IsEthCall` to `true` when it’s a call, and `IsGasEstimation` to `true` when it’s estimating gas

### Step 10: update `graphql/graphql.go`

Update usages of `doCall` and `DoCall` by simply setting `IsEthCall` to `true` when it’s a call, and `IsGasEstimation` to `true` when it’s estimating gas
