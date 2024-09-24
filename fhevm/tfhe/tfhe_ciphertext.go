package tfhe

/*
#include "tfhe_wrappers.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Represents a TFHE ciphertext type, i.e. its bit capacity.
type FheUintType uint8

const (
	FheBool     FheUintType = 0
	FheUint4    FheUintType = 1
	FheUint8    FheUintType = 2
	FheUint16   FheUintType = 3
	FheUint32   FheUintType = 4
	FheUint64   FheUintType = 5
	FheUint128  FheUintType = 6
	FheUint160  FheUintType = 7
	FheUint2048 FheUintType = 11
)

// The version to use when computing ciphertext hashes.
const HashVersion = 0

func (t FheUintType) String() string {
	switch t {
	case FheBool:
		return "fheBool"
	case FheUint4:
		return "fheUint4"
	case FheUint8:
		return "fheUint8"
	case FheUint16:
		return "fheUint16"
	case FheUint32:
		return "fheUint32"
	case FheUint64:
		return "fheUint64"
	case FheUint128:
		return "fheUint128"
	case FheUint160:
		return "fheUint160"
	case FheUint2048:
		return "fheUint2048"
	default:
		return "unknown FheUintType"
	}
}

func (t FheUintType) NumBits() uint {
	switch t {
	case FheBool:
		return 1
	case FheUint4:
		return 4
	case FheUint8:
		return 8
	case FheUint16:
		return 16
	case FheUint32:
		return 32
	case FheUint64:
		return 64
	case FheUint128:
		return 128
	case FheUint160:
		return 160
	case FheUint2048:
		return 2048
	default:
		panic("unknown FheUintType")
	}
}

func IsValidFheType(t byte) bool {
	u := uint8(t)
	if u < uint8(FheBool) || (u > uint8(FheUint160) && u != uint8(FheUint2048)) {
		return false
	}
	return true
}

// Represents an expanded TFHE ciphertext.
type TfheCiphertext struct {
	Serialization []byte
	Hash          *common.Hash
	FheUintType   FheUintType
}

func (ct *TfheCiphertext) Type() FheUintType {
	return ct.FheUintType
}
func boolBinaryNotSupportedOp(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("bool is not supported")
}

func boolBinaryScalarNotSupportedOp(lhs unsafe.Pointer, rhs C.bool) (unsafe.Pointer, error) {
	return nil, errors.New("bool is not supported")
}

func fheUint160BinaryNotSupportedOp(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("fheUint160 is not supported")
}

func fheUint2048BinaryNotSupportedOp(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("fheUint2048 is not supported")
}

func fheUint160BinaryScalarNotSupportedOp(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error) {
	return nil, errors.New("fheUint160 is not supported")
}

func fheUint2048BinarScalaryNotSupportedOp(lhs unsafe.Pointer, rhs C.U2048) (unsafe.Pointer, error) {
	return nil, errors.New("fheUint2048 is not supported")
}

func boolUnaryNotSupportedOp(lhs unsafe.Pointer) (unsafe.Pointer, error) {
	return nil, errors.New("bool is not supported")
}

// Deserializes `in` and returns a C pointer to the ciphertext.
// Expects that the caller will destroy the returned ciphertext via destroyCiphertext().
func Deserialize(in []byte, t FheUintType) unsafe.Pointer {
	switch t {
	case FheBool:
		return C.deserialize_fhe_bool(toDynamicBufferView(in))
	case FheUint4:
		return C.deserialize_fhe_uint4(toDynamicBufferView(in))
	case FheUint8:
		return C.deserialize_fhe_uint8(toDynamicBufferView(in))
	case FheUint16:
		return C.deserialize_fhe_uint16(toDynamicBufferView(in))
	case FheUint32:
		return C.deserialize_fhe_uint32(toDynamicBufferView(in))
	case FheUint64:
		return C.deserialize_fhe_uint64(toDynamicBufferView(in))
	case FheUint160:
		return C.deserialize_fhe_uint160(toDynamicBufferView(in))
	case FheUint2048:
		return C.deserialize_fhe_uint2048(toDynamicBufferView(in))
	default:
		panic("Deserialize: unexpected ciphertext type")
	}
}

// Destroys the ciphertext that is pointed to by `ptr`.
func destroyCiphertext(ptr unsafe.Pointer, t FheUintType) {
	switch t {
	case FheBool:
		C.destroy_fhe_bool(ptr)
	case FheUint4:
		C.destroy_fhe_uint4(ptr)
	case FheUint8:
		C.destroy_fhe_uint8(ptr)
	case FheUint16:
		C.destroy_fhe_uint16(ptr)
	case FheUint32:
		C.destroy_fhe_uint32(ptr)
	case FheUint64:
		C.destroy_fhe_uint64(ptr)
	case FheUint160:
		C.destroy_fhe_uint160(ptr)
	case FheUint2048:
		C.destroy_fhe_uint2048(ptr)
	default:
		panic("destroyCiphertext: unexpected ciphertext type")
	}
}

// Expects that the caller will destroy the pointer via destroyCiphertext().
func (ct *TfheCiphertext) DeserializeToPtr() unsafe.Pointer {
	return Deserialize(ct.Serialize(), ct.FheUintType)
}

// Deserializes a TFHE ciphertext.
func (ct *TfheCiphertext) Deserialize(in []byte, t FheUintType) error {
	ptr := Deserialize(in, t)
	if ptr == nil {
		return fmt.Errorf("%s ciphertext deserialization failed", t.String())
	}
	destroyCiphertext(ptr, t)
	ct.FheUintType = t
	ct.Serialization = in
	ct.computeHash()
	return nil
}

// Deserializes a compact TFHE ciphetext.
// Note: After the compact TFHE ciphertext has been serialized, subsequent calls to serialize()
// will produce non-compact ciphertext serialziations.
func (ct *TfheCiphertext) DeserializeCompact(in []byte, t FheUintType) error {
	switch t {
	case FheBool:
		ptr := C.deserialize_compact_fhe_bool(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheBool ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_bool(ptr)
		if err != nil {
			return err
		}
	case FheUint4:
		ptr := C.deserialize_compact_fhe_uint4(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint4 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint4(ptr)
		if err != nil {
			return err
		}
	case FheUint8:
		ptr := C.deserialize_compact_fhe_uint8(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint8 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			return err
		}
	case FheUint16:
		ptr := C.deserialize_compact_fhe_uint16(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint16 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			return err
		}
	case FheUint32:
		ptr := C.deserialize_compact_fhe_uint32(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint32 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			return err
		}
	case FheUint64:
		ptr := C.deserialize_compact_fhe_uint64(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint64 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint64(ptr)
		if err != nil {
			return err
		}
	case FheUint160:
		ptr := C.deserialize_compact_fhe_uint160(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint160 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint160(ptr)
		if err != nil {
			return err
		}
	case FheUint2048:
		ptr := C.deserialize_compact_fhe_uint2048(toDynamicBufferView((in)))
		if ptr == nil {
			return errors.New("compact FheUint2048 ciphertext deserialization failed")
		}
		var err error
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint2048(ptr)
		if err != nil {
			return err
		}
	default:
		panic("deserializeCompact: unexpected ciphertext type")
	}
	ct.FheUintType = t
	ct.computeHash()
	return nil
}

// Encrypts a value as a TFHE ciphertext, using the compact public FHE key.
// The resulting ciphertext is automaticaly expanded.
func (ct *TfheCiphertext) Encrypt(value big.Int, t FheUintType) *TfheCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case FheBool:
		val := false
		if value.Uint64() > 0 {
			val = true
		}
		ptr = C.public_key_encrypt_fhe_bool(pks, C.bool(val))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_bool(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint4:
		ptr = C.public_key_encrypt_fhe_uint4(pks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint4(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint8:
		ptr = C.public_key_encrypt_fhe_uint8(pks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint16:
		ptr = C.public_key_encrypt_fhe_uint16(pks, C.uint16_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint32:
		ptr = C.public_key_encrypt_fhe_uint32(pks, C.uint32_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint64:
		ptr = C.public_key_encrypt_fhe_uint64(pks, C.uint64_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint64(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint160:
		input, err := bigIntToU256(&value)
		if err != nil {
			panic(err)
		}
		ptr = C.public_key_encrypt_fhe_uint160(pks, input)
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint160(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint2048:
		input, err := bigIntToU2048(&value)
		if err != nil {
			panic(err)
		}
		ptr = C.public_key_encrypt_fhe_uint2048(pks, input)
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint2048(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("encrypt: unexpected ciphertext type")
	}
	ct.FheUintType = t
	ct.computeHash()
	return ct
}

func (ct *TfheCiphertext) TrivialEncrypt(value big.Int, t FheUintType) *TfheCiphertext {
	var ptr unsafe.Pointer
	var err error
	switch t {
	case FheBool:
		val := false
		if value.Uint64() > 0 {
			val = true
		}
		ptr = C.trivial_encrypt_fhe_bool(sks, C.bool(val))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_bool(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint4:
		ptr = C.trivial_encrypt_fhe_uint4(sks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint4(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint8:
		ptr = C.trivial_encrypt_fhe_uint8(sks, C.uint8_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint8(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint16:
		ptr = C.trivial_encrypt_fhe_uint16(sks, C.uint16_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint16(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint32:
		ptr = C.trivial_encrypt_fhe_uint32(sks, C.uint32_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint32(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint64:
		ptr = C.trivial_encrypt_fhe_uint64(sks, C.uint64_t(value.Uint64()))
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint64(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint160:
		input, err := bigIntToU256(&value)
		if err != nil {
			panic(err)
		}
		ptr = C.trivial_encrypt_fhe_uint160(sks, input)
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint160(ptr)
		if err != nil {
			panic(err)
		}
	case FheUint2048:
		input, err := bigIntToU2048(&value)
		if err != nil {
			panic(err)
		}
		ptr = C.trivial_encrypt_fhe_uint2048(sks, input)
		ct.Serialization, err = serialize(ptr, t)
		C.destroy_fhe_uint2048(ptr)
		if err != nil {
			panic(err)
		}
	default:
		panic("trivialEncrypt: unexpected ciphertext type")
	}
	ct.FheUintType = t
	ct.computeHash()
	return ct
}

func (ct *TfheCiphertext) Serialize() []byte {
	return ct.Serialization
}

func (ct *TfheCiphertext) executeUnaryCiphertextOperation(rhs *TfheCiphertext,
	opBool func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op4 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op8 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op16 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op32 func(ct unsafe.Pointer) (unsafe.Pointer, error),
	op64 func(ct unsafe.Pointer) (unsafe.Pointer, error)) (*TfheCiphertext, error) {

	res := new(TfheCiphertext)
	res.FheUintType = ct.FheUintType
	res_ser := &C.DynamicBuffer{}
	switch ct.FheUintType {
	case FheBool:
		ct_ptr := C.deserialize_fhe_bool(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("bool unary op deserialization failed")
		}
		defer C.destroy_fhe_bool(ct_ptr)
		res_ptr, err := opBool(ct_ptr)
		defer C.destroy_fhe_bool(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("bool unary op failed")
		}
		ret := C.serialize_fhe_bool(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("bool unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint4:
		ct_ptr := C.deserialize_fhe_uint4(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("8 bit unary op deserialization failed")
		}
		defer C.destroy_fhe_uint4(ct_ptr)
		res_ptr, err := op4(ct_ptr)
		defer C.destroy_fhe_uint4(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("8 bit unary op failed")
		}
		ret := C.serialize_fhe_uint4(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("8 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint8:
		ct_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("8 bit unary op deserialization failed")
		}
		defer C.destroy_fhe_uint8(ct_ptr)
		res_ptr, err := op8(ct_ptr)
		defer C.destroy_fhe_uint8(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("8 bit unary op failed")
		}
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("8 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		ct_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("16 bit unary op deserialization failed")
		}
		defer C.destroy_fhe_uint16(ct_ptr)
		res_ptr, err := op16(ct_ptr)
		defer C.destroy_fhe_uint16(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("16 bit op failed")
		}
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("16 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		ct_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("32 bit unary op deserialization failed")
		}
		defer C.destroy_fhe_uint32(ct_ptr)
		res_ptr, err := op16(ct_ptr)
		defer C.destroy_fhe_uint32(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("32 bit op failed")
		}
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("32 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		ct_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((ct.Serialization)))
		if ct_ptr == nil {
			return nil, errors.New("64 bit unary op deserialization failed")
		}
		defer C.destroy_fhe_uint64(ct_ptr)
		res_ptr, err := op64(ct_ptr)
		defer C.destroy_fhe_uint64(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("64 bit op failed")
		}
		ret := C.serialize_fhe_uint64(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("64 bit unary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("unary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TfheCiphertext) executeBinaryCiphertextOperation(rhs *TfheCiphertext,
	opBool func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op4 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op8 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op16 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op32 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op64 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op160 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	op2048 func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error),
	returnBool bool) (*TfheCiphertext, error) {
	if lhs.FheUintType != rhs.FheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(TfheCiphertext)
	if returnBool {
		res.FheUintType = FheBool
	} else {
		res.FheUintType = lhs.FheUintType
	}
	res_ser := &C.DynamicBuffer{}
	switch lhs.FheUintType {
	case FheBool:
		lhs_ptr := C.deserialize_fhe_bool(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_bool(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(rhs_ptr)
		res_ptr, err := opBool(lhs_ptr, rhs_ptr)
		defer C.destroy_fhe_bool(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("bool binary op failed")
		}
		ret := C.serialize_fhe_bool(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("bool binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint4:
		lhs_ptr := C.deserialize_fhe_uint4(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint4(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint4(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint4(rhs_ptr)
		res_ptr, err := op4(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint4(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("4 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint4(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("4 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint8(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint8(rhs_ptr)
		res_ptr, err := op8(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint8(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint8(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("8 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint16(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint16(rhs_ptr)
		res_ptr, err := op16(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint16(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint16(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("8 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint32(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint32(rhs_ptr)
		res_ptr, err := op32(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint32(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}

		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint32(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("32 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		lhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint64(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint64(rhs_ptr)
		res_ptr, err := op64(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint64(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("64 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint64(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("64 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint160:
		lhs_ptr := C.deserialize_fhe_uint160(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("160 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint160(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint160(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("160 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint160(rhs_ptr)
		res_ptr, err := op160(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint160(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("160 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint160(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("160 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint2048:
		lhs_ptr := C.deserialize_fhe_uint2048(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("2048 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint2048(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint2048(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("2048 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint2048(rhs_ptr)
		res_ptr, err := op2048(lhs_ptr, rhs_ptr)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint2048(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("2048 bit binary op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool binary op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint2048(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("2048 bit binary op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("binary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (first *TfheCiphertext) executeTernaryCiphertextOperation(lhs *TfheCiphertext, rhs *TfheCiphertext,
	op4 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op8 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op16 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op32 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op64 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer,
	op160 func(first unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer) (*TfheCiphertext, error) {
	if lhs.FheUintType != rhs.FheUintType {
		return nil, errors.New("ternary operations are only well-defined for identical types")
	}

	res := new(TfheCiphertext)
	res.FheUintType = lhs.FheUintType
	res_ser := &C.DynamicBuffer{}
	switch lhs.FheUintType {
	case FheUint4:
		lhs_ptr := C.deserialize_fhe_uint4(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint4(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint4(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("4 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint4(rhs_ptr)
		first_ptr := C.deserialize_fhe_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(first_ptr)
		res_ptr := op4(first_ptr, lhs_ptr, rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("4 bit binary op failed")
		}
		defer C.destroy_fhe_uint4(res_ptr)
		ret := C.serialize_fhe_uint4(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("4 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint8(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("8 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint8(rhs_ptr)
		first_ptr := C.deserialize_fhe_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(first_ptr)
		res_ptr := op8(first_ptr, lhs_ptr, rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("8 bit binary op failed")
		}
		defer C.destroy_fhe_uint8(res_ptr)
		ret := C.serialize_fhe_uint8(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("8 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint16(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("16 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint16(rhs_ptr)
		first_ptr := C.deserialize_fhe_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(first_ptr)
		res_ptr := op16(first_ptr, lhs_ptr, rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("16 bit binary op failed")
		}
		defer C.destroy_fhe_uint16(res_ptr)
		ret := C.serialize_fhe_uint16(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("16 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint32(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("32 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint32(rhs_ptr)
		first_ptr := C.deserialize_fhe_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(first_ptr)
		res_ptr := op32(first_ptr, lhs_ptr, rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("32 bit binary op failed")
		}
		defer C.destroy_fhe_uint32(res_ptr)
		ret := C.serialize_fhe_uint32(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("32 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		lhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint64(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("64 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint64(rhs_ptr)
		first_ptr := C.deserialize_fhe_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(first_ptr)
		res_ptr := op64(first_ptr, lhs_ptr, rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("64 bit binary op failed")
		}
		defer C.destroy_fhe_uint64(res_ptr)
		ret := C.serialize_fhe_uint64(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("64 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint160:
		lhs_ptr := C.deserialize_fhe_uint160(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("160 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint160(lhs_ptr)
		rhs_ptr := C.deserialize_fhe_uint160(toDynamicBufferView((rhs.Serialization)))
		if rhs_ptr == nil {
			return nil, errors.New("160 bit binary op deserialization failed")
		}
		defer C.destroy_fhe_uint160(rhs_ptr)
		first_ptr := C.deserialize_fhe_bool(toDynamicBufferView((first.Serialization)))
		if first_ptr == nil {
			return nil, errors.New("bool binary op deserialization failed")
		}
		defer C.destroy_fhe_bool(first_ptr)
		res_ptr := op160(first_ptr, lhs_ptr, rhs_ptr)
		if res_ptr == nil {
			return nil, errors.New("160 bit binary op failed")
		}
		defer C.destroy_fhe_uint160(res_ptr)
		ret := C.serialize_fhe_uint160(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("160 bit binary op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("ternary op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

// Update: Switched 'rhs' from uint64 to *big.Int to enable 160-bit operations (eq,ne).
func (lhs *TfheCiphertext) executeBinaryScalarOperation(rhs *big.Int,
	opBool func(lhs unsafe.Pointer, rhs C.bool) (unsafe.Pointer, error),
	op4 func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error),
	op8 func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error),
	op16 func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error),
	op32 func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error),
	op64 func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error),
	op160 func(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error),
	op2048 func(lhs unsafe.Pointer, rhs C.U2048) (unsafe.Pointer, error),
	returnBool bool) (*TfheCiphertext, error) {
	res := new(TfheCiphertext)
	if returnBool {
		res.FheUintType = FheBool
	} else {
		res.FheUintType = lhs.FheUintType
	}
	rhs_uint64 := rhs.Uint64()
	res_ser := &C.DynamicBuffer{}
	switch lhs.FheUintType {
	case FheBool:
		lhs_ptr := C.deserialize_fhe_bool(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("bool scalar op deserialization failed")
		}
		defer C.destroy_fhe_bool(lhs_ptr)
		scalar := C.bool(rhs_uint64 == 1)
		res_ptr, err := opBool(lhs_ptr, scalar)
		defer C.destroy_fhe_bool(res_ptr)
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("bool scalar op failed")
		}
		ret := C.serialize_fhe_bool(res_ptr, res_ser)
		if ret != 0 {
			return nil, errors.New("bool scalar op serialization failed")
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint4:
		lhs_ptr := C.deserialize_fhe_uint4(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("4 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint4(lhs_ptr)
		scalar := C.uint8_t(rhs_uint64)
		res_ptr, err := op4(lhs_ptr, scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint4(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("4 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint4(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("4 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint8:
		lhs_ptr := C.deserialize_fhe_uint8(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("8 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint8(lhs_ptr)
		scalar := C.uint8_t(rhs_uint64)
		res_ptr, err := op8(lhs_ptr, scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint8(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("8 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint8(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("8 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint16:
		lhs_ptr := C.deserialize_fhe_uint16(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("16 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint16(lhs_ptr)
		scalar := C.uint16_t(rhs_uint64)
		res_ptr, err := op16(lhs_ptr, scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint16(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("16 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint16(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("16 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint32:
		lhs_ptr := C.deserialize_fhe_uint32(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("32 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint32(lhs_ptr)
		scalar := C.uint32_t(rhs_uint64)
		res_ptr, err := op32(lhs_ptr, scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint32(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("32 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint32(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("32 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint64:
		lhs_ptr := C.deserialize_fhe_uint64(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("64 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint64(lhs_ptr)
		scalar := C.uint64_t(rhs_uint64)
		res_ptr, err := op64(lhs_ptr, scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint64(res_ptr)
		}
		if err != nil {
			return nil, err
		}
		if res_ptr == nil {
			return nil, errors.New("64 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint64(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("64 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint160:
		lhs_ptr := C.deserialize_fhe_uint160(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("160 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint160(lhs_ptr)

		scalar, err := bigIntToU256(rhs)
		if err != nil {
			return nil, err
		}

		res_ptr, err := op160(lhs_ptr, *scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint160(res_ptr)
		}
		if err != nil {
			return nil, err
		}

		if res_ptr == nil {
			return nil, errors.New("160 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint160(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("160 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	case FheUint2048:
		lhs_ptr := C.deserialize_fhe_uint2048(toDynamicBufferView((lhs.Serialization)))
		if lhs_ptr == nil {
			return nil, errors.New("2048 bit scalar op deserialization failed")
		}
		defer C.destroy_fhe_uint2048(lhs_ptr)

		scalar, err := bigIntToU2048(rhs)
		if err != nil {
			return nil, err
		}

		res_ptr, err := op2048(lhs_ptr, *scalar)
		if returnBool {
			defer C.destroy_fhe_bool(res_ptr)
		} else {
			defer C.destroy_fhe_uint2048(res_ptr)
		}
		if err != nil {
			return nil, err
		}

		if res_ptr == nil {
			return nil, errors.New("2048 bit scalar op failed")
		}
		if returnBool {
			ret := C.serialize_fhe_bool(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("bool scalar op serialization failed")
			}
		} else {
			ret := C.serialize_fhe_uint2048(res_ptr, res_ser)
			if ret != 0 {
				return nil, errors.New("160 bit scalar op serialization failed")
			}
		}
		res.Serialization = C.GoBytes(unsafe.Pointer(res_ser.pointer), C.int(res_ser.length))
		C.destroy_dynamic_buffer(res_ser)
	default:
		panic("scalar op unexpected ciphertext type")
	}
	res.computeHash()
	return res, nil
}

func (lhs *TfheCiphertext) Add(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.add_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarAdd(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_add_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_add_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_add_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_add_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_add_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Sub(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.sub_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarSub(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_sub_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_sub_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_sub_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_sub_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_sub_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Mul(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.mul_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarMul(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_mul_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_mul_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_mul_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_mul_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_mul_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarDiv(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_div_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_div_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_div_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_div_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_div_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarRem(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rem_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rem_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_rem_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_rem_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_rem_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Bitand(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_fhe_bool(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitand_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Bitor(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_fhe_bool(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitor_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Bitxor(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_fhe_bool(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.bitxor_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Shl(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shl_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarShl(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shl_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shl_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_shl_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_shl_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_shl_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Shr(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.shr_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp,
		fheUint2048BinaryNotSupportedOp,
		false)
}

func (lhs *TfheCiphertext) ScalarShr(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shr_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_shr_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_shr_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_shr_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_shr_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Rotl(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotl_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotl_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotl_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotl_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotl_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarRotl(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rotl_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rotl_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_rotl_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_rotl_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_rotl_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Rotr(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotr_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotr_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotr_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotr_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.rotr_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp,
		fheUint2048BinaryNotSupportedOp,
		false)
}

func (lhs *TfheCiphertext) ScalarRotr(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rotr_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_rotr_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_rotr_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_rotr_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_rotr_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Eq(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint160(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.eq_fhe_uint2048(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TfheCiphertext) ScalarEq(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint160(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.U2048) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint2048(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TfheCiphertext) Ne(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint160(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ne_fhe_uint2048(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TfheCiphertext) ScalarNe(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ne_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ne_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_ne_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_ne_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_ne_fhe_uint64(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.U256) (unsafe.Pointer, error) {
			return C.scalar_ne_fhe_uint160(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.U2048) (unsafe.Pointer, error) {
			return C.scalar_eq_fhe_uint2048(lhs, rhs, sks), nil
		},
		true)
}

func (lhs *TfheCiphertext) Ge(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.ge_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp,
		fheUint2048BinaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) ScalarGe(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ge_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_ge_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_ge_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_ge_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_ge_fhe_uint64(lhs, rhs, sks), nil
		}, fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) Gt(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.gt_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp,
		fheUint2048BinaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) ScalarGt(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_gt_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_gt_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_gt_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_gt_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_gt_fhe_uint64(lhs, rhs, sks), nil
		}, fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) Le(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.le_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp,
		fheUint2048BinaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) ScalarLe(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_le_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_le_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_le_fhe_uint16(lhs, rhs, sks), nil

		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_le_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_le_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) Lt(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.lt_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp,
		fheUint2048BinaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) ScalarLt(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_lt_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_lt_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_lt_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_lt_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_lt_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp,
		true)
}

func (lhs *TfheCiphertext) Min(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.min_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarMin(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_min_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_min_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_min_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_min_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_min_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Max(rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return lhs.executeBinaryCiphertextOperation(rhs,
		boolBinaryNotSupportedOp,
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.max_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryNotSupportedOp, fheUint2048BinaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) ScalarMax(rhs *big.Int) (*TfheCiphertext, error) {
	return lhs.executeBinaryScalarOperation(rhs,
		boolBinaryScalarNotSupportedOp,
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_max_fhe_uint4(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint8_t) (unsafe.Pointer, error) {
			return C.scalar_max_fhe_uint8(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint16_t) (unsafe.Pointer, error) {
			return C.scalar_max_fhe_uint16(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint32_t) (unsafe.Pointer, error) {
			return C.scalar_max_fhe_uint32(lhs, rhs, sks), nil
		},
		func(lhs unsafe.Pointer, rhs C.uint64_t) (unsafe.Pointer, error) {
			return C.scalar_max_fhe_uint64(lhs, rhs, sks), nil
		},
		fheUint160BinaryScalarNotSupportedOp, fheUint2048BinarScalaryNotSupportedOp, false)
}

func (lhs *TfheCiphertext) Neg() (*TfheCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		boolUnaryNotSupportedOp,
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_fhe_uint4(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_fhe_uint8(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_fhe_uint16(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_fhe_uint32(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.neg_fhe_uint64(lhs, sks), nil
		})
}

func (lhs *TfheCiphertext) Not() (*TfheCiphertext, error) {
	return lhs.executeUnaryCiphertextOperation(lhs,
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_fhe_bool(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_fhe_uint4(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_fhe_uint8(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_fhe_uint16(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_fhe_uint32(lhs, sks), nil
		},
		func(lhs unsafe.Pointer) (unsafe.Pointer, error) {
			return C.not_fhe_uint64(lhs, sks), nil
		})
}

func (condition *TfheCiphertext) IfThenElse(lhs *TfheCiphertext, rhs *TfheCiphertext) (*TfheCiphertext, error) {
	return condition.executeTernaryCiphertextOperation(lhs, rhs,
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint4(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint8(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint16(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint32(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint64(condition, lhs, rhs, sks)
		},
		func(condition unsafe.Pointer, lhs unsafe.Pointer, rhs unsafe.Pointer) unsafe.Pointer {
			return C.if_then_else_fhe_uint160(condition, lhs, rhs, sks)
		})
}

func (ct *TfheCiphertext) CastTo(castToType FheUintType) (*TfheCiphertext, error) {
	if ct.FheUintType == castToType {
		return nil, errors.New("casting to same type is not supported")
	}

	res := new(TfheCiphertext)
	res.FheUintType = castToType

	switch ct.FheUintType {
	case FheBool:
		switch castToType {
		case FheUint4:
			from_ptr := C.deserialize_fhe_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheBool ciphertext")
			}
			to_ptr := C.cast_bool_4(from_ptr, sks)
			C.destroy_fhe_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheBool to FheUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint8:
			from_ptr := C.deserialize_fhe_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheBool ciphertext")
			}
			to_ptr := C.cast_bool_8(from_ptr, sks)
			C.destroy_fhe_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheBool to FheUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheBool ciphertext")
			}
			to_ptr := C.cast_bool_16(from_ptr, sks)
			C.destroy_fhe_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheBool to FheUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheBool ciphertext")
			}
			to_ptr := C.cast_bool_32(from_ptr, sks)
			C.destroy_fhe_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheBool to FheUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_bool(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheBool ciphertext")
			}
			to_ptr := C.cast_bool_64(from_ptr, sks)
			C.destroy_fhe_bool(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheBool to FheUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("castTo: unexpected type to cast to")
		}
	case FheUint4:
		switch castToType {
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint4 ciphertext")
			}
			to_ptr := C.cast_4_8(from_ptr, sks)
			C.destroy_fhe_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint4 to FheUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint4 ciphertext")
			}
			to_ptr := C.cast_4_16(from_ptr, sks)
			C.destroy_fhe_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint4 to FheUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint4 ciphertext")
			}
			to_ptr := C.cast_4_32(from_ptr, sks)
			C.destroy_fhe_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint4 to FheUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint4(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint4 ciphertext")
			}
			to_ptr := C.cast_4_64(from_ptr, sks)
			C.destroy_fhe_uint4(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint4 to FheUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("castTo: unexpected type to cast to")
		}
	case FheUint8:
		switch castToType {
		case FheUint4:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_4(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_16(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_32(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint8 ciphertext")
			}
			to_ptr := C.cast_8_64(from_ptr, sks)
			C.destroy_fhe_uint8(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint8 to FheUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("castTo: unexpected type to cast to")
		}
	case FheUint16:
		switch castToType {
		case FheUint4:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_4(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_8(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_32(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint16 ciphertext")
			}
			to_ptr := C.cast_16_64(from_ptr, sks)
			C.destroy_fhe_uint16(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint16 to FheUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("castTo: unexpected type to cast to")
		}
	case FheUint32:
		switch castToType {
		case FheUint4:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_4(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_8(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_16(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint64:
			from_ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint32 ciphertext")
			}
			to_ptr := C.cast_32_64(from_ptr, sks)
			C.destroy_fhe_uint32(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint32 to FheUint64")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint64(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("castTo: unexpected type to cast to")
		}
	case FheUint64:
		switch castToType {
		case FheUint4:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_4(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint4")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint4(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint8:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_8(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint8")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint8(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint16:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_16(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint16")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint16(to_ptr)
			if err != nil {
				return nil, err
			}
		case FheUint32:
			from_ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.Serialization))
			if from_ptr == nil {
				return nil, errors.New("castTo failed to deserialize FheUint64 ciphertext")
			}
			to_ptr := C.cast_64_32(from_ptr, sks)
			C.destroy_fhe_uint64(from_ptr)
			if to_ptr == nil {
				return nil, errors.New("castTo failed to cast FheUint64 to FheUint32")
			}
			var err error
			res.Serialization, err = serialize(to_ptr, castToType)
			C.destroy_fhe_uint32(to_ptr)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("castTo: unexpected type to cast to")
		}
	case FheUint160:
		return castFheUint160To(ct, castToType)
	default:
		return nil, fmt.Errorf("castTo: unexpected type to cast from")
	}
	res.computeHash()
	return res, nil
}

func (ct *TfheCiphertext) Decrypt() (big.Int, error) {
	if cks == nil {
		return *new(big.Int).SetUint64(0), errors.New("cks is not initialized")
	}
	var value uint64
	var ret C.int
	switch ct.FheUintType {
	case FheBool:
		ptr := C.deserialize_fhe_bool(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheBool")
		}
		var result C.bool
		ret = C.decrypt_fhe_bool(cks, ptr, &result)
		C.destroy_fhe_bool(ptr)
		if result {
			value = 1
		} else {
			value = 0
		}
	case FheUint4:
		ptr := C.deserialize_fhe_uint4(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint4")
		}
		defer C.destroy_fhe_uint4(ptr)
		var result C.uint8_t
		ret = C.decrypt_fhe_uint4(cks, ptr, &result)
		value = uint64(result)
	case FheUint8:
		ptr := C.deserialize_fhe_uint8(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint8")
		}
		defer C.destroy_fhe_uint8(ptr)
		var result C.uint8_t
		ret = C.decrypt_fhe_uint8(cks, ptr, &result)
		value = uint64(result)
	case FheUint16:
		ptr := C.deserialize_fhe_uint16(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint16")
		}
		defer C.destroy_fhe_uint16(ptr)
		var result C.uint16_t
		ret = C.decrypt_fhe_uint16(cks, ptr, &result)
		value = uint64(result)
	case FheUint32:
		ptr := C.deserialize_fhe_uint32(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint32")
		}
		defer C.destroy_fhe_uint32(ptr)
		var result C.uint32_t
		ret = C.decrypt_fhe_uint32(cks, ptr, &result)
		value = uint64(result)
	case FheUint64:
		ptr := C.deserialize_fhe_uint64(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint64")
		}
		defer C.destroy_fhe_uint64(ptr)
		var result C.uint64_t
		ret = C.decrypt_fhe_uint64(cks, ptr, &result)
		value = uint64(result)
	case FheUint160:
		ptr := C.deserialize_fhe_uint160(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint160")
		}
		defer C.destroy_fhe_uint160(ptr)
		var result C.U256
		ret = C.decrypt_fhe_uint160(cks, ptr, &result)
		if ret != 0 {
			return *new(big.Int).SetUint64(0), errors.New("failed to decrypt FheUint160")
		}
		resultBigInt := *u256ToBigInt(&result)
		return resultBigInt, nil
	case FheUint2048:
		ptr := C.deserialize_fhe_uint2048(toDynamicBufferView(ct.Serialization))
		if ptr == nil {
			return *new(big.Int).SetUint64(0), errors.New("failed to deserialize FheUint2048")
		}
		defer C.destroy_fhe_uint2048(ptr)
		var result C.U2048
		ret = C.decrypt_fhe_uint2048(cks, ptr, &result)
		if ret != 0 {
			return *new(big.Int).SetUint64(0), errors.New("failed to decrypt FheUint160")
		}
		resultBigInt := *u2048ToBigInt(&result)
		return resultBigInt, nil
	default:
		panic("decrypt: unexpected ciphertext type")
	}
	if ret != 0 {
		return *new(big.Int).SetUint64(0), errors.New("decrypt failed")
	}
	return *new(big.Int).SetUint64(value), nil
}

func (ct *TfheCiphertext) computeHash() {
	hash := common.BytesToHash(crypto.Keccak256(ct.Serialization))
	hash[31] = HashVersion
	hash[30] = byte(ct.FheUintType)
	ct.Hash = &hash
}

func (ct *TfheCiphertext) GetHash() common.Hash {
	if ct.Hash != nil {
		return *ct.Hash
	}
	ct.computeHash()
	return *ct.Hash
}

// Caller is responsible for freeing the returned pointers.
func arrayToCiphertextPointerArray(arr []*TfheCiphertext, expectedType FheUintType) []unsafe.Pointer {
	ret := make([]unsafe.Pointer, 0, len(arr))
	for _, ct := range arr {
		if ct.Type() != expectedType {
			return ret
		}
		ptr := ct.DeserializeToPtr()
		if ptr == nil {
			return ret
		}
		ret = append(ret, ptr)
	}
	return ret
}

func destroyCiphertextPointerArray(arr []unsafe.Pointer, t FheUintType) {
	for _, p := range arr {
		destroyCiphertext(p, t)
	}
}

func EqArray(lhs []*TfheCiphertext, rhs []*TfheCiphertext) (*TfheCiphertext, error) {
	result := new(TfheCiphertext)
	if len(lhs) == 0 && len(rhs) == 0 {
		// If both lhs and rhs are empty, return a trivial encryption of true.
		result.TrivialEncrypt(*big.NewInt(1), FheBool)
	} else if len(lhs) != len(rhs) {
		// If lengths are different, return a trivial encryption of false.
		result.TrivialEncrypt(*big.NewInt(0), FheBool)
	} else {
		// Make sure types are the same.
		lhsType := lhs[0].Type()
		rhsType := rhs[0].Type()
		if lhsType != rhsType {
			msg := fmt.Sprintf("EqArray: lhs type %d is different from rhs type %d", lhsType, rhsType)
			return nil, errors.New(msg)
		}
		numOfElements := len(lhs)
		elementsType := lhsType

		// Convert to C pointers.
		lhsPtrs := arrayToCiphertextPointerArray(lhs, elementsType)
		defer destroyCiphertextPointerArray(lhsPtrs, elementsType)
		rhsPtrs := arrayToCiphertextPointerArray(rhs, elementsType)
		defer destroyCiphertextPointerArray(rhsPtrs, elementsType)

		// Make sure all are of the same type.
		if len(lhsPtrs) != numOfElements || len(rhsPtrs) != numOfElements {
			return nil, errors.New("EqArray: elements are of different types")
		}

		// Do the FHE computation.
		var resultPtr unsafe.Pointer
		switch elementsType {
		case FheUint4:
			resultPtr = C.eq_fhe_array_uint4(unsafe.Pointer(&lhsPtrs[0]), (C.size_t)(numOfElements), unsafe.Pointer(&rhsPtrs[0]), (C.size_t)(numOfElements), sks)
		case FheUint8:
			resultPtr = C.eq_fhe_array_uint8(unsafe.Pointer(&lhsPtrs[0]), (C.size_t)(numOfElements), unsafe.Pointer(&rhsPtrs[0]), (C.size_t)(numOfElements), sks)
		case FheUint16:
			resultPtr = C.eq_fhe_array_uint16(unsafe.Pointer(&lhsPtrs[0]), (C.size_t)(numOfElements), unsafe.Pointer(&rhsPtrs[0]), (C.size_t)(numOfElements), sks)
		case FheUint32:
			resultPtr = C.eq_fhe_array_uint32(unsafe.Pointer(&lhsPtrs[0]), (C.size_t)(numOfElements), unsafe.Pointer(&rhsPtrs[0]), (C.size_t)(numOfElements), sks)
		case FheUint64:
			resultPtr = C.eq_fhe_array_uint64(unsafe.Pointer(&lhsPtrs[0]), (C.size_t)(numOfElements), unsafe.Pointer(&rhsPtrs[0]), (C.size_t)(numOfElements), sks)
		default:
			return nil, fmt.Errorf("EqArray: unsupported ciphertext type %d", elementsType)
		}
		if resultPtr == nil {
			return nil, errors.New("EqArray: FHE computation failed")
		}
		defer C.destroy_fhe_bool(resultPtr)
		ser := &C.DynamicBuffer{}
		ret := C.serialize_fhe_bool(resultPtr, ser)
		if ret != 0 {
			return nil, errors.New("EqArray: bool serialization failed")
		}
		defer C.destroy_dynamic_buffer(ser)
		result.Serialization = C.GoBytes(unsafe.Pointer(ser.pointer), C.int(ser.length))
		result.FheUintType = FheBool
		result.computeHash()
	}
	return result, nil
}
