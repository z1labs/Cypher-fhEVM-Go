package crypto

import (
	"github.com/ethereum/go-ethereum/common"
	evm "github.com/ethereum/go-ethereum/crypto"
)

// CreateProtectedStorageAddress creates an ethereum contract address for protected storage
// given the corresponding contract address
func CreateProtectedStorageContractAddress(b common.Address) common.Address {
	return evm.CreateAddress(b, 0)
}
