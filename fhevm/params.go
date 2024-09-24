package fhevm

import "github.com/zama-ai/fhevm-go/fhevm/tfhe"

// This file contains default gas costs of fhEVM-related operations.
// Users can change the values based on specific requirements in their blockchain.

// Base gas costs of existing EVM operations. Used for setting gas costs relative to them.
// These constants are used just for readability.
const EvmNetSstoreInitGas uint64 = 20000
const AdjustFHEGas uint64 = 10000
const ColdSloadCostEIP2929 uint64 = 2100

const GetNonExistentCiphertextGas uint64 = ColdSloadCostEIP2929

const DeserializeCiphertextGas uint64 = 30

// Base costs of fhEVM SSTORE and SLOAD operations.
// TODO: We don't take whether the slot is cold or warm into consideration.
const SstoreFheUint4Gas = EvmNetSstoreInitGas + 1000
const SloadFheUint4Gas = ColdSloadCostEIP2929 + 100

func DefaultFhevmParams() FhevmParams {
	return FhevmParams{
		GasCosts: DefaultGasCosts(),
	}
}

type FhevmParams struct {
	GasCosts GasCosts
}

type GasCosts struct {
	FheCast                  uint64
	FhePubKey                uint64
	FheAddSub                map[tfhe.FheUintType]uint64
	FheBitwiseOp             map[tfhe.FheUintType]uint64
	FheMul                   map[tfhe.FheUintType]uint64
	FheScalarMul             map[tfhe.FheUintType]uint64
	FheScalarDiv             map[tfhe.FheUintType]uint64
	FheScalarRem             map[tfhe.FheUintType]uint64
	FheShift                 map[tfhe.FheUintType]uint64
	FheScalarShift           map[tfhe.FheUintType]uint64
	FheEq                    map[tfhe.FheUintType]uint64
	FheArrayEqBigArrayFactor uint64 // TODO: either rename or come up with a better solution
	FheLe                    map[tfhe.FheUintType]uint64
	FheMinMax                map[tfhe.FheUintType]uint64
	FheScalarMinMax          map[tfhe.FheUintType]uint64
	FheNot                   map[tfhe.FheUintType]uint64
	FheNeg                   map[tfhe.FheUintType]uint64
	FheTrivialEncrypt        map[tfhe.FheUintType]uint64
	FheRand                  map[tfhe.FheUintType]uint64
	FheIfThenElse            map[tfhe.FheUintType]uint64
	FheVerify                map[tfhe.FheUintType]uint64
	FheGetCiphertext         map[tfhe.FheUintType]uint64
	FheStorageSstoreGas      map[tfhe.FheUintType]uint64
	FheStorageSloadGas       map[tfhe.FheUintType]uint64
}

func DefaultGasCosts() GasCosts {
	return GasCosts{
		FheCast:   200,
		FhePubKey: 50,
		FheAddSub: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  55000 + AdjustFHEGas,
			tfhe.FheUint8:  84000 + AdjustFHEGas,
			tfhe.FheUint16: 123000 + AdjustFHEGas,
			tfhe.FheUint32: 152000 + AdjustFHEGas,
			tfhe.FheUint64: 178000 + AdjustFHEGas,
		},
		FheBitwiseOp: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:   16000 + AdjustFHEGas,
			tfhe.FheUint4:  22000 + AdjustFHEGas,
			tfhe.FheUint8:  24000 + AdjustFHEGas,
			tfhe.FheUint16: 24000 + AdjustFHEGas,
			tfhe.FheUint32: 25000 + AdjustFHEGas,
			tfhe.FheUint64: 28000 + AdjustFHEGas,
		},
		FheMul: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  140000 + AdjustFHEGas,
			tfhe.FheUint8:  187000 + AdjustFHEGas,
			tfhe.FheUint16: 252000 + AdjustFHEGas,
			tfhe.FheUint32: 349000 + AdjustFHEGas,
			tfhe.FheUint64: 631000 + AdjustFHEGas,
		},
		FheScalarMul: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  78000 + AdjustFHEGas,
			tfhe.FheUint8:  149000 + AdjustFHEGas,
			tfhe.FheUint16: 198000 + AdjustFHEGas,
			tfhe.FheUint32: 254000 + AdjustFHEGas,
			tfhe.FheUint64: 346000 + AdjustFHEGas,
		},
		FheScalarDiv: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  129000 + AdjustFHEGas,
			tfhe.FheUint8:  228000 + AdjustFHEGas,
			tfhe.FheUint16: 304000 + AdjustFHEGas,
			tfhe.FheUint32: 388000 + AdjustFHEGas,
			tfhe.FheUint64: 574000 + AdjustFHEGas,
		},
		FheScalarRem: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  276000 + AdjustFHEGas,
			tfhe.FheUint8:  450000 + AdjustFHEGas,
			tfhe.FheUint16: 612000 + AdjustFHEGas,
			tfhe.FheUint32: 795000 + AdjustFHEGas,
			tfhe.FheUint64: 1095000 + AdjustFHEGas,
		},
		FheShift: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  106000 + AdjustFHEGas,
			tfhe.FheUint8:  123000 + AdjustFHEGas,
			tfhe.FheUint16: 143000 + AdjustFHEGas,
			tfhe.FheUint32: 173000 + AdjustFHEGas,
			tfhe.FheUint64: 217000 + AdjustFHEGas,
		},
		FheScalarShift: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  25000 + AdjustFHEGas,
			tfhe.FheUint8:  25000 + AdjustFHEGas,
			tfhe.FheUint16: 25000 + AdjustFHEGas,
			tfhe.FheUint32: 25000 + AdjustFHEGas,
			tfhe.FheUint64: 28000 + AdjustFHEGas,
		},
		FheEq: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:    41000 + AdjustFHEGas,
			tfhe.FheUint8:    43000 + AdjustFHEGas,
			tfhe.FheUint16:   44000 + AdjustFHEGas,
			tfhe.FheUint32:   72000 + AdjustFHEGas,
			tfhe.FheUint64:   76000 + AdjustFHEGas,
			tfhe.FheUint160:  80000 + AdjustFHEGas,
			tfhe.FheUint2048: 160000 + AdjustFHEGas,
		},
		FheArrayEqBigArrayFactor: 1000,
		FheLe: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  60000 + AdjustFHEGas,
			tfhe.FheUint8:  72000 + AdjustFHEGas,
			tfhe.FheUint16: 95000 + AdjustFHEGas,
			tfhe.FheUint32: 118000 + AdjustFHEGas,
			tfhe.FheUint64: 146000 + AdjustFHEGas,
		},
		FheMinMax: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  111000 + AdjustFHEGas,
			tfhe.FheUint8:  118000 + AdjustFHEGas,
			tfhe.FheUint16: 143000 + AdjustFHEGas,
			tfhe.FheUint32: 173000 + AdjustFHEGas,
			tfhe.FheUint64: 200000 + AdjustFHEGas,
		},
		FheScalarMinMax: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  111000 + AdjustFHEGas,
			tfhe.FheUint8:  118000 + AdjustFHEGas,
			tfhe.FheUint16: 140000 + AdjustFHEGas,
			tfhe.FheUint32: 154000 + AdjustFHEGas,
			tfhe.FheUint64: 182000 + AdjustFHEGas,
		},
		FheNot: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:   22000 + AdjustFHEGas,
			tfhe.FheUint4:  23000 + AdjustFHEGas,
			tfhe.FheUint8:  24000 + AdjustFHEGas,
			tfhe.FheUint16: 25000 + AdjustFHEGas,
			tfhe.FheUint32: 26000 + AdjustFHEGas,
			tfhe.FheUint64: 27000 + AdjustFHEGas,
		},
		FheNeg: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  50000 + AdjustFHEGas,
			tfhe.FheUint8:  85000 + AdjustFHEGas,
			tfhe.FheUint16: 121000 + AdjustFHEGas,
			tfhe.FheUint32: 150000 + AdjustFHEGas,
			tfhe.FheUint64: 189000 + AdjustFHEGas,
		},
		// As of now, verification costs only cover ciphertext deserialization and assume there is no ZKPoK to verify.
		FheVerify: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:     200 + 5000, // TODO: Requires an FheUint160 comparisson via FheEq. Make it cheaper than that, though. Need to fix that.
			tfhe.FheUint4:    200 + 500,
			tfhe.FheUint8:    200 + 500,
			tfhe.FheUint16:   300 + 500,
			tfhe.FheUint32:   400 + 500,
			tfhe.FheUint64:   800 + 500,
			tfhe.FheUint160:  1200 + 500,
			tfhe.FheUint2048: 2000 + 500,
		},
		FheTrivialEncrypt: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:     100,
			tfhe.FheUint4:    100,
			tfhe.FheUint8:    100,
			tfhe.FheUint16:   200,
			tfhe.FheUint32:   300,
			tfhe.FheUint64:   600,
			tfhe.FheUint160:  700,
			tfhe.FheUint2048: 900,
		},
		// TODO: These will change once we have an FHE-based random generaration.
		FheRand: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  EvmNetSstoreInitGas + 100000,
			tfhe.FheUint8:  EvmNetSstoreInitGas + 100000,
			tfhe.FheUint16: EvmNetSstoreInitGas + 100000,
			tfhe.FheUint32: EvmNetSstoreInitGas + 100000,
			tfhe.FheUint64: EvmNetSstoreInitGas + 100000,
		},
		FheIfThenElse: map[tfhe.FheUintType]uint64{
			tfhe.FheUint4:  35000 + AdjustFHEGas,
			tfhe.FheUint8:  37000 + AdjustFHEGas,
			tfhe.FheUint16: 37000 + AdjustFHEGas,
			tfhe.FheUint32: 40000 + AdjustFHEGas,
			tfhe.FheUint64: 43000 + AdjustFHEGas,
		},
		FheGetCiphertext: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:     10000,
			tfhe.FheUint8:    12000,
			tfhe.FheUint16:   14000,
			tfhe.FheUint32:   18000,
			tfhe.FheUint64:   28000,
			tfhe.FheUint160:  50000,
			tfhe.FheUint2048: 100000,
		},
		// TODO: The values here are chosen somewhat arbitrarily.
		// Also, we don't take into account whether a ciphertext existed (either "current" or "original") for the given handle.
		// Finally, costs are likely to change in the future.
		FheStorageSstoreGas: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:     SstoreFheUint4Gas / 2,
			tfhe.FheUint4:    SstoreFheUint4Gas,
			tfhe.FheUint8:    SstoreFheUint4Gas * 2,
			tfhe.FheUint16:   SstoreFheUint4Gas * 4,
			tfhe.FheUint32:   SstoreFheUint4Gas * 8,
			tfhe.FheUint64:   SstoreFheUint4Gas * 16,
			tfhe.FheUint128:  SstoreFheUint4Gas * 32,
			tfhe.FheUint160:  SstoreFheUint4Gas * 40,
			tfhe.FheUint2048: SstoreFheUint4Gas * 120,
		},
		FheStorageSloadGas: map[tfhe.FheUintType]uint64{
			tfhe.FheBool:     SloadFheUint4Gas / 2,
			tfhe.FheUint4:    SloadFheUint4Gas,
			tfhe.FheUint8:    SloadFheUint4Gas * 2,
			tfhe.FheUint16:   SloadFheUint4Gas * 4,
			tfhe.FheUint32:   SloadFheUint4Gas * 8,
			tfhe.FheUint64:   SloadFheUint4Gas * 16,
			tfhe.FheUint128:  SloadFheUint4Gas * 32,
			tfhe.FheUint160:  SloadFheUint4Gas * 40,
			tfhe.FheUint2048: SloadFheUint4Gas * 120, // TODO: technically, it is more than 10 times bigger than 160 bits
		},
	}
}

var TxDataFractionalGasFactor uint64 = 4

func TxDataFractionalGas(originalGas uint64) (fractionalGas uint64) {
	return originalGas / TxDataFractionalGasFactor
}
