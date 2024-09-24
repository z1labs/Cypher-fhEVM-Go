package tfhe

/*
#cgo linux CFLAGS: -O3 -I../../tfhe-rs/target/release -I../../tfhe-rs/target/release/deps
#cgo linux LDFLAGS: -L../../tfhe-rs/target/release -l:libtfhe.a -L../../tfhe-rs/target/release/deps -l:libtfhe_c_api_dynamic_buffer.a -lm
#cgo darwin CFLAGS: -O3 -I../../tfhe-rs/target/release -I../../tfhe-rs/target/release/deps
#cgo darwin LDFLAGS: -framework Security -L../../tfhe-rs/target/release -ltfhe -L../../tfhe-rs/target/release/deps -ltfhe_c_api_dynamic_buffer -lm

#include "tfhe_wrappers.h"

*/
import "C"

import (
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"unsafe"
)

func toDynamicBufferView(in []byte) C.DynamicBufferView {
	return C.DynamicBufferView{
		pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
		length:  (C.size_t)(len(in)),
	}
}

func serialize(ptr unsafe.Pointer, t FheUintType) ([]byte, error) {
	out := &C.DynamicBuffer{}
	var ret C.int
	switch t {
	case FheBool:
		ret = C.serialize_fhe_bool(ptr, out)
	case FheUint4:
		ret = C.serialize_fhe_uint4(ptr, out)
	case FheUint8:
		ret = C.serialize_fhe_uint8(ptr, out)
	case FheUint16:
		ret = C.serialize_fhe_uint16(ptr, out)
	case FheUint32:
		ret = C.serialize_fhe_uint32(ptr, out)
	case FheUint64:
		ret = C.serialize_fhe_uint64(ptr, out)
	case FheUint160:
		ret = C.serialize_fhe_uint160(ptr, out)
	case FheUint2048:
		ret = C.serialize_fhe_uint2048(ptr, out)
	default:
		panic("serialize: unexpected ciphertext type")
	}
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize a ciphertext")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser, nil
}

func SerializePublicKey() ([]byte, error) {
	if pks == nil {
		return nil, errors.New("serialize: no public key available")
	}
	out := &C.DynamicBuffer{}
	ret := C.serialize_compact_public_key(pks, out)
	if ret != 0 {
		return nil, errors.New("serialize: failed to serialize public key")
	}
	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser, nil
}

func EncryptAndSerializeCompact(value uint64, fheUintType FheUintType) []byte {
	out := &C.DynamicBuffer{}
	switch fheUintType {
	case FheBool:
		val := false
		if value == 1 {
			val = true
		}
		C.public_key_encrypt_and_serialize_fhe_bool_list(pks, C.bool(val), out)
	case FheUint4:
		C.public_key_encrypt_and_serialize_fhe_uint4_list(pks, C.uint8_t(value), out)
	case FheUint8:
		C.public_key_encrypt_and_serialize_fhe_uint8_list(pks, C.uint8_t(value), out)
	case FheUint16:
		C.public_key_encrypt_and_serialize_fhe_uint16_list(pks, C.uint16_t(value), out)
	case FheUint32:
		C.public_key_encrypt_and_serialize_fhe_uint32_list(pks, C.uint32_t(value), out)
	case FheUint64:
		C.public_key_encrypt_and_serialize_fhe_uint64_list(pks, C.uint64_t(value), out)
	case FheUint160:
		value_big := new(big.Int).SetUint64(value)
		input, err := bigIntToU256(value_big)
		if err != nil {
			panic(err)
		}
		C.public_key_encrypt_and_serialize_fhe_uint160_list(pks, input, out)
	case FheUint2048:
		value_big := new(big.Int).SetUint64(value)
		input, err := bigIntToU2048(value_big)
		if err != nil {
			panic(err)
		}
		C.public_key_encrypt_and_serialize_fhe_uint2048_list(pks, input, out)
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_dynamic_buffer(out)
	return ser
}

// bigIntToU256 uses x to convert big.Int to U256
func bigIntToU256(value *big.Int) (*C.U256, error) {
	// Convert big.Int to 32-byte big-endian slice
	if len(value.Bytes()) > 32 {
		return nil, fmt.Errorf("big.Int too large for U256")
	}
	bytes := make([]byte, 32)
	value.FillBytes(bytes)

	var result C.U256
	ret := C.u256_from_big_endian_bytes((*C.uint8_t)(unsafe.Pointer(&bytes[0])), C.size_t(32), &result)
	if ret != 0 {
		return nil, fmt.Errorf("failed to convert big.Int to U256: %d", ret)
	}
	return &result, nil
}

func bigIntToU2048(value *big.Int) (*C.U2048, error) {
	if len(value.Bytes()) > 256 {
		return nil, fmt.Errorf("big.Int too large for U2048")
	}
	bytes := make([]byte, 256)
	value.FillBytes(bytes)

	var result C.U2048
	ret := C.U2048_from_big_endian_bytes((*C.uint8_t)(unsafe.Pointer(&bytes[0])), C.size_t(256), &result)
	if ret != 0 {
		return nil, fmt.Errorf("failed to convert big.Int to U2048: %d", ret)
	}
	return &result, nil
}

// u256ToBigInt converts a U256 to a *big.Int.
func u256ToBigInt(value *C.U256) *big.Int {
	// Allocate a byte slice with enough space (32 bytes for U256)
	buf := make([]byte, 32)

	// Call the C function to fill the buffer with the big-endian bytes of U256
	C.u256_big_endian_bytes(*value, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))

	return new(big.Int).SetBytes(buf)
}

func u2048ToBigInt(value *C.U2048) *big.Int {
	buf := make([]byte, 256)
	C.U2048_big_endian_bytes(*value, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return new(big.Int).SetBytes(buf)
}

func EncryptAndSerializeCompact160List(values []big.Int) ([]byte, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("EncryptAndSerializeCompact160List empty array given")
	}
	inputArray := make([]C.U256, len(values))
	for i, v := range values {
		u256, err := bigIntToU256(&v)
		if err != nil {
			return nil, err
		}
		inputArray[i] = *u256
	}

	var list *C.CompactFheUint160List
	ret := C.compact_fhe_uint160_list_try_encrypt_with_compact_public_key_u256(&inputArray[0], (C.size_t)(len(inputArray)), (*C.CompactPublicKey)(pks), &list)
	if ret != 0 {
		return nil, fmt.Errorf("EncryptAndSerializeCompact160List failed to encrypt with %d", ret)
	}
	defer C.compact_fhe_uint160_list_destroy(list)

	ser := C.DynamicBuffer{}
	ret = C.compact_fhe_uint160_list_serialize(list, &ser)
	if ret != 0 {
		return nil, fmt.Errorf("EncryptAndSerializeCompact160List failed to serialize with %d", ret)
	}
	defer C.destroy_dynamic_buffer(&ser)

	return C.GoBytes(unsafe.Pointer(ser.pointer), C.int(ser.length)), nil
}

func DeserializeAndExpandCompact160List(in []byte) ([]*TfheCiphertext, error) {
	var list *C.CompactFheUint160List
	ret := C.compact_fhe_uint160_list_deserialize(toDynamicBufferView(in), &list)
	if ret != 0 {
		return nil, fmt.Errorf("DeserializeCompact160List failed to deserialize list with %d", ret)
	}
	defer C.compact_fhe_uint160_list_destroy(list)

	var len C.size_t
	ret = C.compact_fhe_uint160_list_len(list, &len)
	if ret != 0 {
		return nil, fmt.Errorf("DeserializeCompact160List failed to get list length with %d", ret)
	}
	if len == 0 {
		return nil, fmt.Errorf("DeserializeCompact160List length is 0")
	}

	expanded := make([]*C.FheUint160, len)
	ret = C.compact_fhe_uint160_list_expand(list, &expanded[0], len)
	if ret != 0 {
		return nil, fmt.Errorf("DeserializeCompact160List failed to expand list with %d", ret)
	}
	defer func() {
		for _, c := range expanded {
			C.destroy_fhe_uint160(unsafe.Pointer(c))
		}
	}()

	cts := make([]*TfheCiphertext, 0, len)
	for _, c := range expanded {
		ser, err := serialize(unsafe.Pointer(c), FheUint160)
		if err != nil {
			return nil, err
		}
		ct := new(TfheCiphertext)
		ct.Serialization = ser
		ct.FheUintType = FheUint160
		ct.computeHash()
		cts = append(cts, ct)
	}
	return cts, nil
}

func EncryptAndSerializeCompact2048List(values []big.Int) ([]byte, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("EncryptAndSerializeCompact2048List empty array given")
	}
	inputArray := make([]C.U2048, len(values))
	for i, v := range values {
		u2048, err := bigIntToU2048(&v)
		if err != nil {
			return nil, err
		}
		inputArray[i] = *u2048
	}

	var list *C.CompactFheUint2048List
	ret := C.compact_fhe_uint2048_list_try_encrypt_with_compact_public_key_u2048(&inputArray[0], (C.size_t)(len(inputArray)), (*C.CompactPublicKey)(pks), &list)
	if ret != 0 {
		return nil, fmt.Errorf("EncryptAndSerializeCompact2048List failed to encrypt with %d", ret)
	}
	defer C.compact_fhe_uint2048_list_destroy(list)

	ser := C.DynamicBuffer{}
	ret = C.compact_fhe_uint2048_list_serialize(list, &ser)
	if ret != 0 {
		return nil, fmt.Errorf("EncryptAndSerializeCompact2048List failed to serialize with %d", ret)
	}
	defer C.destroy_dynamic_buffer(&ser)

	return C.GoBytes(unsafe.Pointer(ser.pointer), C.int(ser.length)), nil
}

func DeserializeAndExpandCompact2048List(in []byte) ([]*TfheCiphertext, error) {
	var list *C.CompactFheUint2048List
	ret := C.compact_fhe_uint2048_list_deserialize(toDynamicBufferView(in), &list)
	if ret != 0 {
		return nil, fmt.Errorf("DeserializeCompact2048List failed to deserialize list with %d", ret)
	}
	defer C.compact_fhe_uint2048_list_destroy(list)

	var len C.size_t
	ret = C.compact_fhe_uint2048_list_len(list, &len)
	if ret != 0 {
		return nil, fmt.Errorf("DeserializeCompact2048List failed to get list length with %d", ret)
	}
	if len == 0 {
		return nil, fmt.Errorf("DeserializeCompact2048List length is 0")
	}

	expanded := make([]*C.FheUint2048, len)
	ret = C.compact_fhe_uint2048_list_expand(list, &expanded[0], len)
	if ret != 0 {
		return nil, fmt.Errorf("DeserializeCompact2048List failed to expand list with %d", ret)
	}
	defer func() {
		for _, c := range expanded {
			C.destroy_fhe_uint2048(unsafe.Pointer(c))
		}
	}()

	cts := make([]*TfheCiphertext, 0, len)
	for _, c := range expanded {
		ser, err := serialize(unsafe.Pointer(c), FheUint2048)
		if err != nil {
			return nil, err
		}
		ct := new(TfheCiphertext)
		ct.Serialization = ser
		ct.FheUintType = FheUint2048
		ct.computeHash()
		cts = append(cts, ct)
	}
	return cts, nil
}

func castFheUint160To(ct *TfheCiphertext, fheUintType FheUintType) (*TfheCiphertext, error) {
	ptr160 := C.deserialize_fhe_uint160(toDynamicBufferView(ct.Serialize()))
	if ptr160 == nil {
		return nil, errors.New("CastFheUint160To failed to deserialize FheUint160 ciphertext")
	}
	defer C.destroy_fhe_uint160(ptr160)

	var err error
	var resPtr unsafe.Pointer
	switch fheUintType {
	case FheBool:
		var ctNe *TfheCiphertext
		ctNe, err = ct.ScalarNe(big.NewInt(0))
		if err != nil {
			return nil, err
		}
		ctNe.computeHash()
		return ctNe, nil
	case FheUint4:
		resPtr = C.cast_160_4(ptr160, sks)
		defer C.destroy_fhe_uint4(resPtr)
	case FheUint8:
		resPtr = C.cast_160_8(ptr160, sks)
		defer C.destroy_fhe_uint8(resPtr)
	case FheUint16:
		resPtr = C.cast_160_16(ptr160, sks)
		defer C.destroy_fhe_uint16(resPtr)
	case FheUint32:
		resPtr = C.cast_160_32(ptr160, sks)
		defer C.destroy_fhe_uint32(resPtr)
	case FheUint64:
		resPtr = C.cast_160_64(ptr160, sks)
		defer C.destroy_fhe_uint64(resPtr)
	default:
		return nil, fmt.Errorf("castFheUint160To invalid type to FheUint160 to: %s", fheUintType.String())
	}

	res := new(TfheCiphertext)
	res.Serialization, err = serialize(resPtr, fheUintType)
	if err != nil {
		return nil, err
	}
	res.FheUintType = fheUintType
	res.computeHash()
	return res, nil
}
