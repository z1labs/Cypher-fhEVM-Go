package tfhe

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/bits"
	"os"
	"testing"
)

// generate keys if not present
func setup() {
	if !AllGlobalKeysPresent() {
		fmt.Println("INFO: initializing global keys in tests")
		InitGlobalKeysWithNewKeys()
	}
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}

func TfheEncryptDecrypt(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheBool:
		val.SetUint64(1)
	case FheUint4:
		val.SetUint64(2)
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	case FheUint64:
		val.SetUint64(13333377777777777)

	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct := new(TfheCiphertext)
	ct.Encrypt(val, fheUintType)
	res, err := ct.Decrypt()

	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if res.Cmp(&val) != 0 {
		t.Fatalf("Decryption result does not match the original value. Expected %s, got %s", val.Text(10), res.Text(10))
	}
}

func TfheTrivialEncryptDecrypt(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheBool:
		val.SetUint64(1)
	case FheUint4:
		val.SetUint64(2)
	case FheUint8:
		val.SetUint64(2)
	case FheUint16:
		val.SetUint64(1337)
	case FheUint32:
		val.SetUint64(1333337)
	case FheUint64:
		val.SetUint64(13333377777777777)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct := new(TfheCiphertext)
	ct.TrivialEncrypt(val, fheUintType)
	res, err := ct.Decrypt()
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if res.Cmp(&val) != 0 {
		t.Fatalf("Decryption result does not match the original value. Expected %s, got %s", val.Text(10), res.Text(10))
	}
}

func TfheSerializeDeserialize(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheBool:
		val = *big.NewInt(1)
	case FheUint4:
		val = *big.NewInt(2)
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	case FheUint64:
		val = *big.NewInt(13333377777777777)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct1 := new(TfheCiphertext)
	ct1.Encrypt(val, fheUintType)
	ct1Ser := ct1.Serialize()
	ct2 := new(TfheCiphertext)
	err := ct2.Deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}
}

func TfheSerializeDeserializeCompact(t *testing.T, fheUintType FheUintType) {
	var val uint64
	switch fheUintType {
	case FheBool:
		val = 1
	case FheUint4:
		val = 2
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	case FheUint64:
		val = 13333377777777777
	case FheUint160:
		val = 13333377777777777
	}

	ser := EncryptAndSerializeCompact(val, fheUintType)
	ct1 := new(TfheCiphertext)
	err := ct1.DeserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("ct1 compact deserialization failed")
	}
	ct1Ser := ct1.Serialize()

	ct2 := new(TfheCiphertext)
	err = ct2.Deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("ct2 deserialization failed")
	}

	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("serialization is non-deterministic")
	}

	decrypted, err := ct2.Decrypt()
	if err != nil || uint64(decrypted.Uint64()) != val {
		t.Fatalf("decrypted value is incorrect")
	}
}

func TfheTrivialSerializeDeserialize(t *testing.T, fheUintType FheUintType) {
	var val big.Int
	switch fheUintType {
	case FheBool:
		val = *big.NewInt(1)
	case FheUint4:
		val = *big.NewInt(2)
	case FheUint8:
		val = *big.NewInt(2)
	case FheUint16:
		val = *big.NewInt(1337)
	case FheUint32:
		val = *big.NewInt(1333337)
	case FheUint64:
		val = *big.NewInt(13333377777777777)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		val.SetBytes(byteValue)
	}
	ct1 := new(TfheCiphertext)
	ct1.TrivialEncrypt(val, fheUintType)
	ct1Ser := ct1.Serialize()
	ct2 := new(TfheCiphertext)
	err := ct2.Deserialize(ct1Ser, fheUintType)
	if err != nil {
		t.Fatalf("deserialization failed")
	}
	ct2Ser := ct2.Serialize()
	if !bytes.Equal(ct1Ser, ct2Ser) {
		t.Fatalf("trivial serialization is non-deterministic")
	}
}

func TfheDeserializeFailure(t *testing.T, fheUintType FheUintType) {
	ct := new(TfheCiphertext)
	input := make([]byte, 1)
	input[0] = 42
	err := ct.Deserialize(input, fheUintType)
	if err == nil {
		t.Fatalf("deserialization must have failed")
	}
}

func TfheDeserializeCompact(t *testing.T, fheUintType FheUintType) {
	var val uint64
	switch fheUintType {
	case FheBool:
		val = 1
	case FheUint4:
		val = 2
	case FheUint8:
		val = 2
	case FheUint16:
		val = 1337
	case FheUint32:
		val = 1333337
	case FheUint64:
		val = 13333377777777777
	}

	ser := EncryptAndSerializeCompact(val, fheUintType)
	ct := new(TfheCiphertext)
	err := ct.DeserializeCompact(ser, fheUintType)
	if err != nil {
		t.Fatalf("compact deserialization failed")
	}
	decryptedVal, err := ct.Decrypt()
	if err != nil || uint64(decryptedVal.Uint64()) != val {
		t.Fatalf("compact deserialization wrong decryption")
	}
}

func TfheDeserializeCompactFailure(t *testing.T, fheUintType FheUintType) {
	ct := new(TfheCiphertext)
	err := ct.DeserializeCompact(make([]byte, 10), fheUintType)
	if err == nil {
		t.Fatalf("compact deserialization must have failed")
	}
}

func TfheAdd(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Add(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarAdd(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Add(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarAdd(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheSub(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Sub(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarSub(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337777777777)
	}
	expected := new(big.Int).Sub(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarSub(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheMul(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(133)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Mul(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarMul(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(133)
	}
	expected := new(big.Int).Mul(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarMul(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarDiv(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(4)
		b.SetUint64(2)
	case FheUint8:
		a.SetUint64(4)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(49)
		b.SetUint64(144)
	case FheUint32:
		a.SetUint64(70)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Div(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarDiv(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarRem(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(4)
		b.SetUint64(2)
	case FheUint8:
		a.SetUint64(4)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(49)
		b.SetUint64(144)
	case FheUint32:
		a.SetUint64(70)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rem(&a, &b)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarRem(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheBitAnd(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheBool:
		a.SetUint64(1)
		b.SetUint64(1)
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() & b.Uint64()
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Bitand(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheBitOr(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() | b.Uint64()
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Bitor(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheBitXor(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := a.Uint64() ^ b.Uint64()
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Bitxor(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheShl(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Shl(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarShl(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
	}
	expected := new(big.Int).Lsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarShl(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheShr(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Shr(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheScalarShr(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	expected := new(big.Int).Rsh(&a, uint(b.Uint64()))
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarShr(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected.Uint64() {
		t.Fatalf("%d != %d", expected.Uint64(), res.Uint64())
	}
}

func TfheRotl(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	var expected uint64
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), int(b.Uint64())))
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), int(b.Uint64())))
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
		expected = uint64(bits.RotateLeft16(uint16(a.Uint64()), int(b.Uint64())))
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
		expected = uint64(bits.RotateLeft32(uint32(a.Uint64()), int(b.Uint64())))
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
		expected = bits.RotateLeft64(a.Uint64(), int(b.Uint64()))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Rotl(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarRotl(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	var expected uint64
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), int(b.Uint64())))
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), int(b.Uint64())))
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
		expected = uint64(bits.RotateLeft16(uint16(a.Uint64()), int(b.Uint64())))
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
		expected = uint64(bits.RotateLeft32(uint32(a.Uint64()), int(b.Uint64())))
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(45)
		expected = uint64(bits.RotateLeft64(a.Uint64(), int(b.Uint64())))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarRotl(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheRotr(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	var expected uint64
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), -int(b.Uint64())))
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), -int(b.Uint64())))
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
		expected = uint64(bits.RotateLeft16(uint16(a.Uint64()), -int(b.Uint64())))
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
		expected = uint64(bits.RotateLeft32(uint32(a.Uint64()), -int(b.Uint64())))
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
		expected = uint64(bits.RotateLeft64(a.Uint64(), -int(b.Uint64())))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Rotr(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarRotr(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	var expected uint64
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), -int(b.Uint64())))
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
		expected = uint64(bits.RotateLeft8(uint8(a.Uint64()), -int(b.Uint64())))
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
		expected = uint64(bits.RotateLeft16(uint16(a.Uint64()), -int(b.Uint64())))
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
		expected = uint64(bits.RotateLeft32(uint32(a.Uint64()), -int(b.Uint64())))
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
		expected = uint64(bits.RotateLeft64(a.Uint64(), -int(b.Uint64())))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarRotr(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheEq(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(2)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(137)
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(1337)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetBytes(byteValue)
	case FheUint2048:
		hexValue := "12345676876661323221435343778899"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetBytes(byteValue)
	}

	var expected uint64
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 1
	} else {
		expected = 0
	}

	// TODO: use encryption for FheUint2048 when available in tfhe-rs
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Eq(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}

}

func TfheScalarEq(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetBytes(byteValue)
	}
	var expected uint64
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 1
	} else {
		expected = 0
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarEq(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheNe(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(2)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(2)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(137)
	case FheUint64:
		a.SetUint64(1337)
		b.SetUint64(1337)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetUint64(8888)
	case FheUint2048:
		hexValue := "12345676876661323221435343990055"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetUint64(8888)
	}

	var expected uint64
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 0
	} else {
		expected = 1
	}
	// TODO: use encryption for FheUint2048 when available in tfhe-rs
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes, _ := ctA.Ne(ctB)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheScalarNe(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(169)
		b.SetUint64(5)
	case FheUint32:
		a.SetUint64(137)
		b.SetInt64(17)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetUint64(8888)
	}

	var expected uint64
	// No != for big.Int
	expectedPlain := a.Cmp(&b)
	if expectedPlain == 0 {
		expected = 0
	} else {
		expected = 1
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes, _ := ctA.ScalarNe(&b)
	res, err := ctRes.Decrypt()
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", expected, res.Uint64())
	}
}

func TfheGe(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Ge(ctB)
	ctRes2, _ := ctB.Ge(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 1, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarGe(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarGe(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheGt(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Gt(ctB)
	ctRes2, _ := ctB.Gt(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarGt(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarGt(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheLe(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Le(ctB)
	ctRes2, _ := ctB.Le(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarLe(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarLe(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheLt(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Lt(ctB)
	ctRes2, _ := ctB.Lt(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != 1 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheScalarLt(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarLt(&b)
	res1, err := ctRes1.Decrypt()
	if err != nil || res1.Uint64() != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheMin(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Min(ctB)
	ctRes2, _ := ctB.Min(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TfheScalarMin(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarMin(&b)
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != b.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheMax(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(4)
		b.SetUint64(2)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctA.Max(ctB)
	ctRes2, _ := ctB.Max(ctA)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res1.Uint64())
	}
	if err2 != nil || res2.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", b.Uint64(), res2.Uint64())
	}
}

func TfheScalarMax(t *testing.T, fheUintType FheUintType) {
	var a, b big.Int
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13371337)
		b.SetUint64(1337)
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.ScalarMax(&b)
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != a.Uint64() {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
}

func TfheNeg(t *testing.T, fheUintType FheUintType) {
	var a big.Int
	var expected uint64

	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		expected = uint64(uint8(16 - a.Uint64()))
	case FheUint8:
		a.SetUint64(2)
		expected = uint64(-uint8(a.Uint64()))
	case FheUint16:
		a.SetUint64(4283)
		expected = uint64(-uint16(a.Uint64()))
	case FheUint32:
		a.SetUint64(1333337)
		expected = uint64(-uint32(a.Uint64()))
	case FheUint64:
		a.SetUint64(13333377777777777)
		expected = uint64(-uint64(a.Uint64()))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctRes1, _ := ctA.Neg()
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TfheNot(t *testing.T, fheUintType FheUintType) {
	var a big.Int
	var expected uint64
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		expected = uint64(^uint8(a.Uint64()))
	case FheUint8:
		a.SetUint64(2)
		expected = uint64(^uint8(a.Uint64()))
	case FheUint16:
		a.SetUint64(4283)
		expected = uint64(^uint16(a.Uint64()))
	case FheUint32:
		a.SetUint64(1333337)
		expected = uint64(^uint32(a.Uint64()))
	case FheUint64:
		a.SetUint64(13333377777777777)
		expected = uint64(^uint64(a.Uint64()))
	}
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)

	ctRes1, _ := ctA.Not()
	res1, err1 := ctRes1.Decrypt()
	if err1 != nil || res1.Uint64() != expected {
		t.Fatalf("%d != %d", res1.Uint64(), expected)
	}
}

func TfheIfThenElse(t *testing.T, fheUintType FheUintType) {
	var condition, condition2, a, b big.Int
	condition.SetUint64(1)
	condition2.SetUint64(0)
	switch fheUintType {
	case FheUint4:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint8:
		a.SetUint64(2)
		b.SetUint64(1)
	case FheUint16:
		a.SetUint64(4283)
		b.SetUint64(1337)
	case FheUint32:
		a.SetUint64(1333337)
		b.SetUint64(133337)
	case FheUint64:
		a.SetUint64(13333377777777777)
		b.SetUint64(133337)
	case FheUint160:
		hexValue := "12345676876661323221435343"
		hexValue2 := "12345676876661323221435344"
		byteValue, err := hex.DecodeString(hexValue)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		byteValue2, err := hex.DecodeString(hexValue2)
		if err != nil {
			log.Fatalf("Failed to decode hex string: %v", err)
		}
		a.SetBytes(byteValue)
		b.SetBytes(byteValue2)
	}
	ctCondition := new(TfheCiphertext)
	ctCondition.Encrypt(condition, FheBool)
	ctCondition2 := new(TfheCiphertext)
	ctCondition2.Encrypt(condition2, FheBool)
	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintType)
	ctB := new(TfheCiphertext)
	ctB.Encrypt(b, fheUintType)
	ctRes1, _ := ctCondition.IfThenElse(ctA, ctB)
	ctRes2, _ := ctCondition2.IfThenElse(ctA, ctB)
	res1, err1 := ctRes1.Decrypt()
	res2, err2 := ctRes2.Decrypt()
	if err1 != nil || res1.Cmp(&a) != 0 {
		t.Fatalf("%d != %d", 0, res1.Uint64())
	}
	if err2 != nil || res2.Cmp(&b) != 0 {
		t.Fatalf("%d != %d", 0, res2.Uint64())
	}
}

func TfheCast(t *testing.T, fheUintTypeFrom FheUintType, fheUintTypeTo FheUintType) {
	var a big.Int
	switch fheUintTypeFrom {
	case FheUint4:
		a.SetUint64(2)
	case FheUint8:
		a.SetUint64(2)
	case FheUint16:
		a.SetUint64(4283)
	case FheUint32:
		a.SetUint64(1333337)
	case FheUint64:
		a.SetUint64(13333377777777777)
	}

	var modulus uint64
	switch fheUintTypeTo {
	case FheUint4:
		modulus = uint64(math.Pow(2, 4))
	case FheUint8:
		modulus = uint64(math.Pow(2, 8))
	case FheUint16:
		modulus = uint64(math.Pow(2, 16))
	case FheUint32:
		modulus = uint64(math.Pow(2, 32))
	case FheUint64:
		modulus = uint64(math.Pow(2, 64))
	}

	ctA := new(TfheCiphertext)
	ctA.Encrypt(a, fheUintTypeFrom)
	ctRes, err := ctA.CastTo(fheUintTypeTo)
	if err != nil {
		t.Fatal(err)
	}

	if ctRes.FheUintType != fheUintTypeTo {
		t.Fatalf("type %d != type %d", ctA.FheUintType, fheUintTypeTo)
	}
	res, err := ctRes.Decrypt()
	expected := a.Uint64() % modulus
	if err != nil || res.Uint64() != expected {
		t.Fatalf("%d != %d", res.Uint64(), expected)
	}
}

func TfheEqArrayEqual(t *testing.T, fheUintType FheUintType) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), fheUintType))

	rhs := make([]*TfheCiphertext, 0)
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), fheUintType))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), fheUintType))

	result, err := EqArray(lhs, rhs)
	if err != nil {
		t.Fatalf("EqArray failed: %v", err)
	}
	decrypted, err := result.Decrypt()
	if err != nil {
		t.Fatalf("EqArray decrypt failed: %v", err)
	}
	if !decrypted.IsUint64() || decrypted.Uint64() != 1 {
		t.Fatalf("EqArray expected result of 1, got: %s", decrypted.String())
	}
}

func TfheEqArrayCompareToSelf(t *testing.T, fheUintType FheUintType) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), fheUintType))
	rhs := lhs

	result, err := EqArray(lhs, rhs)
	if err != nil {
		t.Fatalf("EqArray failed: %v", err)
	}
	decrypted, err := result.Decrypt()
	if err != nil {
		t.Fatalf("EqArray decrypt failed: %v", err)
	}
	if !decrypted.IsUint64() || decrypted.Uint64() != 1 {
		t.Fatalf("EqArray expected result of 1, got: %s", decrypted.String())
	}
}

func TfheEqArrayNotEqualSameLen(t *testing.T, fheUintType FheUintType) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), fheUintType))

	rhs := make([]*TfheCiphertext, 0)
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(6), fheUintType))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), fheUintType))

	result, err := EqArray(lhs, rhs)
	if err != nil {
		t.Fatalf("EqArray failed: %v", err)
	}
	decrypted, err := result.Decrypt()
	if err != nil {
		t.Fatalf("EqArray decrypt failed: %v", err)
	}
	if !decrypted.IsUint64() || decrypted.Uint64() != 0 {
		t.Fatalf("EqArray expected result of 0, got: %s", decrypted.String())
	}
}

func TfheEqArrayNotEqualDifferentLen(t *testing.T, fheUintType FheUintType) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), fheUintType))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), fheUintType))

	rhs := make([]*TfheCiphertext, 0)
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), fheUintType))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(6), fheUintType))

	result, err := EqArray(lhs, rhs)
	if err != nil {
		t.Fatalf("EqArray failed: %v", err)
	}
	decrypted, err := result.Decrypt()
	if err != nil {
		t.Fatalf("EqArray decrypt failed: %v", err)
	}
	if !decrypted.IsUint64() || decrypted.Uint64() != 0 {
		t.Fatalf("EqArray expected result of 0, got: %s", decrypted.String())
	}
}

func TestTfheEqArrayEqualBothEmpty(t *testing.T) {
	lhs := make([]*TfheCiphertext, 0)
	rhs := make([]*TfheCiphertext, 0)
	result, err := EqArray(lhs, rhs)
	if err != nil {
		t.Fatalf("EqArray failed: %v", err)
	}
	decrypted, err := result.Decrypt()
	if err != nil {
		t.Fatalf("EqArray decrypt failed: %v", err)
	}
	if !decrypted.IsUint64() || decrypted.Uint64() != 1 {
		t.Fatalf("EqArray expected result of 1, got: %s", decrypted.String())
	}
}

func TestTfheEqArrayDifferentTypesInLhs(t *testing.T) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), FheUint32))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), FheUint32))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), FheUint64))

	rhs := make([]*TfheCiphertext, 0)
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), FheUint32))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(6), FheUint32))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), FheUint32))

	_, err := EqArray(lhs, rhs)
	if err == nil {
		t.Fatalf("EqArray expected error")
	}
}

func TestTfheEqArrayDifferentTypesInRhs(t *testing.T) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), FheUint32))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), FheUint32))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), FheUint32))

	rhs := make([]*TfheCiphertext, 0)
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), FheUint32))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(6), FheUint16))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), FheUint32))

	_, err := EqArray(lhs, rhs)
	if err == nil {
		t.Fatalf("EqArray expected error")
	}
}

func TestTfheEqArrayUnsupportedType(t *testing.T) {
	lhs := make([]*TfheCiphertext, 0)
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), FheBool))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(7), FheBool))
	lhs = append(lhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), FheBool))

	rhs := make([]*TfheCiphertext, 0)
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(4), FheBool))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(6), FheBool))
	rhs = append(rhs, new(TfheCiphertext).Encrypt(*big.NewInt(10), FheBool))

	_, err := EqArray(lhs, rhs)
	if err == nil {
		t.Fatalf("EqArray expected error")
	}
}

func TfheCompact160ListSerDeserRoundTrip(t *testing.T, input []big.Int) {
	serList, err := EncryptAndSerializeCompact160List(input)
	if err != nil {
		t.Fatalf("EncryptAndSerializeCompact160List failed with %v", err)
	}
	cts, err := DeserializeAndExpandCompact160List(serList)
	if err != nil {
		t.Fatalf("DeserializeAndExpandCompact160List failed with %v", err)
	}
	if len(cts) != len(input) {
		t.Fatalf("DeserializeAndExpandCompact160List returned %d ciphertexts, expected %d", len(cts), len(input))
	}

	for i, ct := range cts {
		v, err := ct.Decrypt()
		if err != nil {
			t.Fatalf("Decrypt of ct%d failed with %v", i, err)
		}
		if v.Cmp(&input[i]) != 0 {
			t.Fatalf("v%d=%v is not equa to in%d=%v", i, v, i, input[i])
		}
	}
}

func TestTfheCompact160ListSerDeserRoundTrip64Bit(t *testing.T) {
	input := make([]big.Int, 0)
	input = append(input, *big.NewInt(79))
	input = append(input, *big.NewInt(42))
	TfheCompact160ListSerDeserRoundTrip(t, input)
}

func TestTfheCompact160ListSerDeserRoundTrip160Bit(t *testing.T) {
	input := make([]big.Int, 0)
	in1, ok := new(big.Int).SetString("1edd3edac274a90128356fb8caa11bd2", 16)
	if in1 == nil || !ok {
		t.Fatalf("failed to create 128 bit integer")
	}
	in2, ok := new(big.Int).SetString("9f24d93621347ca0832d1a3980750eea", 16)
	if in2 == nil || !ok {
		t.Fatalf("failed to create 128 bit integer")
	}
	in3, ok := new(big.Int).SetString("e80e81fe4402389034f8123d4d2fffe9", 16)
	if in3 == nil || !ok {
		t.Fatalf("failed to create 128 bit integer")
	}
	input = append(input, *in1)
	input = append(input, *in2)
	input = append(input, *in3)
	TfheCompact160ListSerDeserRoundTrip(t, input)
}

func TestTfheCompact160ListEmptyInput(t *testing.T) {
	input := make([]big.Int, 0)
	_, err := EncryptAndSerializeCompact160List(input)
	if err == nil {
		t.Fatalf("EncryptAndSerializeCompact160List must have failed on empty input")
	}
}

func TestTfheEncryptDecryptBool(t *testing.T) {
	TfheEncryptDecrypt(t, FheBool)
}

func TestTfheEncryptDecrypt4(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint4)
}

func TestTfheEncryptDecrypt8(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint8)
}

func TestTfheEncryptDecrypt16(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint16)
}

func TestTfheEncryptDecrypt32(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint32)
}

func TestTfheEncryptDecrypt64(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint64)
}

func TestTfheEncryptDecrypt160(t *testing.T) {
	TfheEncryptDecrypt(t, FheUint160)
}

func TestTfheTrivialEncryptDecryptBool(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheBool)
}

func TestTfheTrivialEncryptDecrypt4(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint4)
}

func TestTfheTrivialEncryptDecrypt8(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint8)
}

func TestTfheTrivialEncryptDecrypt16(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint16)
}

func TestTfheTrivialEncryptDecrypt32(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint32)
}

func TestTfheTrivialEncryptDecrypt64(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint64)
}

func TestTfheTrivialEncryptDecrypt160(t *testing.T) {
	TfheTrivialEncryptDecrypt(t, FheUint160)
}

func TestTfheSerializeDeserializeBool(t *testing.T) {
	TfheSerializeDeserialize(t, FheBool)
}

func TestTfheSerializeDeserialize4(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint4)
}

func TestTfheSerializeDeserialize8(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint8)
}

func TestTfheSerializeDeserialize16(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint16)
}

func TestTfheSerializeDeserialize32(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint32)
}

func TestTfheSerializeDeserialize64(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint64)
}

func TestTfheSerializeDeserialize160(t *testing.T) {
	TfheSerializeDeserialize(t, FheUint160)
}

func TestTfheSerializeDeserializeCompactBool(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheBool)
}

func TestTfheSerializeDeserializeCompact4(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint4)
}

func TestTfheSerializeDeserializeCompact16(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint16)
}

func TestTfheSerializeDeserializeCompact32(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint32)
}

func TestTfheSerializeDeserializeCompact64(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint64)
}

func TestTfheSerializeDeserializeCompact160(t *testing.T) {
	TfheSerializeDeserializeCompact(t, FheUint160)
}

func TestTfheTrivialSerializeDeserializeBool(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheBool)
}

func TestTfheTrivialSerializeDeserialize4(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint4)
}

func TestTfheTrivialSerializeDeserialize8(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint8)
}

func TestTfheTrivialSerializeDeserialize16(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint16)
}

func TestTfheTrivialSerializeDeserialize32(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint32)
}

func TestTfheTrivialSerializeDeserialize64(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint64)
}

func TestTfheTrivialSerializeDeserialize160(t *testing.T) {
	TfheTrivialSerializeDeserialize(t, FheUint160)
}

func TestTfheDeserializeFailureBool(t *testing.T) {
	TfheDeserializeFailure(t, FheBool)
}

func TestTfheDeserializeFailure4(t *testing.T) {
	TfheDeserializeFailure(t, FheUint4)
}

func TestTfheDeserializeFailure8(t *testing.T) {
	TfheDeserializeFailure(t, FheUint8)
}

func TestTfheDeserializeFailure16(t *testing.T) {
	TfheDeserializeFailure(t, FheUint16)
}

func TestTfheDeserializeFailure32(t *testing.T) {
	TfheDeserializeFailure(t, FheUint32)
}

func TestTfheDeserializeFailure64(t *testing.T) {
	TfheDeserializeFailure(t, FheUint64)
}

func TestTfheDeserializeCompactBool(t *testing.T) {
	TfheDeserializeCompact(t, FheBool)
}

func TestTfheDeserializeCompact4(t *testing.T) {
	TfheDeserializeCompact(t, FheUint4)
}

func TestTfheDeserializeCompact8(t *testing.T) {
	TfheDeserializeCompact(t, FheUint8)
}

func TestTfheDeserializeCompact16(t *testing.T) {
	TfheDeserializeCompact(t, FheUint16)
}

func TestTfheDeserializeCompact32(t *testing.T) {
	TfheDeserializeCompact(t, FheUint32)
}

func TestTfheDeserializeCompact64(t *testing.T) {
	TfheDeserializeCompact(t, FheUint64)
}

func TestTfheDeserializeCompactFailureBool(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheBool)
}

func TestTfheDeserializeCompactFailure4(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint4)
}

func TestTfheDeserializeCompactFailure8(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint8)
}

func TestTfheDeserializeCompactFailure16(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint16)
}

func TestTfheDeserializeCompatcFailure32(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint32)
}

func TestTfheDeserializeCompatcFailure64(t *testing.T) {
	TfheDeserializeCompactFailure(t, FheUint64)
}

func TestTfheAdd4(t *testing.T) {
	TfheAdd(t, FheUint4)
}

func TestTfheAdd8(t *testing.T) {
	TfheAdd(t, FheUint8)
}

func TestTfheAdd16(t *testing.T) {
	TfheAdd(t, FheUint16)
}

func TestTfheAdd32(t *testing.T) {
	TfheAdd(t, FheUint32)
}

func TestTfheAdd64(t *testing.T) {
	TfheAdd(t, FheUint64)
}

func TestTfheScalarAdd4(t *testing.T) {
	TfheScalarAdd(t, FheUint4)
}

func TestTfheScalarAdd8(t *testing.T) {
	TfheScalarAdd(t, FheUint8)
}

func TestTfheScalarAdd16(t *testing.T) {
	TfheScalarAdd(t, FheUint16)
}

func TestTfheScalarAdd32(t *testing.T) {
	TfheScalarAdd(t, FheUint32)
}

func TestTfheScalarAdd64(t *testing.T) {
	TfheScalarAdd(t, FheUint32)
}

func TestTfheSub4(t *testing.T) {
	TfheSub(t, FheUint4)
}

func TestTfheSub8(t *testing.T) {
	TfheSub(t, FheUint8)
}

func TestTfheSub16(t *testing.T) {
	TfheSub(t, FheUint16)
}

func TestTfheSub32(t *testing.T) {
	TfheSub(t, FheUint32)
}

func TestTfheSub64(t *testing.T) {
	TfheSub(t, FheUint64)
}

func TestTfheScalarSub4(t *testing.T) {
	TfheScalarSub(t, FheUint4)
}

func TestTfheScalarSub8(t *testing.T) {
	TfheScalarSub(t, FheUint8)
}

func TestTfheScalarSub16(t *testing.T) {
	TfheScalarSub(t, FheUint16)
}

func TestTfheScalarSub32(t *testing.T) {
	TfheScalarSub(t, FheUint32)
}

func TestTfheScalarSub64(t *testing.T) {
	TfheScalarSub(t, FheUint64)
}

func TestTfheMul4(t *testing.T) {
	TfheMul(t, FheUint4)
}

func TestTfheMul8(t *testing.T) {
	TfheMul(t, FheUint8)
}

func TestTfheMul16(t *testing.T) {
	TfheMul(t, FheUint16)
}

func TestTfheMul32(t *testing.T) {
	TfheMul(t, FheUint32)
}

func TestTfheMul64(t *testing.T) {
	TfheMul(t, FheUint64)
}

func TestTfheScalarMul4(t *testing.T) {
	TfheScalarMul(t, FheUint4)
}

func TestTfheScalarMul8(t *testing.T) {
	TfheScalarMul(t, FheUint8)
}

func TestTfheScalarMul16(t *testing.T) {
	TfheScalarMul(t, FheUint16)
}

func TestTfheScalarMul32(t *testing.T) {
	TfheScalarMul(t, FheUint32)
}

func TestTfheScalarMul64(t *testing.T) {
	TfheScalarMul(t, FheUint64)
}

func TestTfheScalarDiv4(t *testing.T) {
	TfheScalarDiv(t, FheUint4)
}

func TestTfheScalarDiv8(t *testing.T) {
	TfheScalarDiv(t, FheUint8)
}

func TestTfheScalarDiv16(t *testing.T) {
	TfheScalarDiv(t, FheUint16)
}

func TestTfheScalarDiv32(t *testing.T) {
	TfheScalarDiv(t, FheUint32)
}

func TestTfheScalarDiv64(t *testing.T) {
	TfheScalarDiv(t, FheUint64)
}

func TestTfheScalarRem4(t *testing.T) {
	TfheScalarRem(t, FheUint4)
}

func TestTfheScalarRem8(t *testing.T) {
	TfheScalarRem(t, FheUint8)
}

func TestTfheScalarRem16(t *testing.T) {
	TfheScalarRem(t, FheUint16)
}

func TestTfheScalarRem32(t *testing.T) {
	TfheScalarRem(t, FheUint32)
}

func TestTfheScalarRem64(t *testing.T) {
	TfheScalarRem(t, FheUint64)
}

func TestTfheBitAnd4(t *testing.T) {
	TfheBitAnd(t, FheUint4)
}

func TestTfheBitAnd8(t *testing.T) {
	TfheBitAnd(t, FheUint8)
}

func TestTfheBitAnd16(t *testing.T) {
	TfheBitAnd(t, FheUint16)
}

func TestTfheBitAnd32(t *testing.T) {
	TfheBitAnd(t, FheUint32)
}

func TestTfheBitAnd64(t *testing.T) {
	TfheBitAnd(t, FheUint64)
}

func TestTfheBitOr4(t *testing.T) {
	TfheBitOr(t, FheUint4)
}

func TestTfheBitOr8(t *testing.T) {
	TfheBitOr(t, FheUint8)
}

func TestTfheBitOr16(t *testing.T) {
	TfheBitOr(t, FheUint16)
}

func TestTfheBitOr32(t *testing.T) {
	TfheBitOr(t, FheUint32)
}

func TestTfheBitOr64(t *testing.T) {
	TfheBitOr(t, FheUint64)
}

func TestTfheBitXor4(t *testing.T) {
	TfheBitXor(t, FheUint4)
}

func TestTfheBitXor8(t *testing.T) {
	TfheBitXor(t, FheUint8)
}

func TestTfheBitXor16(t *testing.T) {
	TfheBitXor(t, FheUint16)
}

func TestTfheBitXor32(t *testing.T) {
	TfheBitXor(t, FheUint32)
}

func TestTfheBitXor64(t *testing.T) {
	TfheBitXor(t, FheUint64)
}

func TestTfheShl4(t *testing.T) {
	TfheShl(t, FheUint4)
}

func TestTfheShl8(t *testing.T) {
	TfheShl(t, FheUint8)
}

func TestTfheShl16(t *testing.T) {
	TfheShl(t, FheUint16)
}

func TestTfheShl32(t *testing.T) {
	TfheShl(t, FheUint32)
}

func TestTfheShl64(t *testing.T) {
	TfheShl(t, FheUint64)
}

func TestTfheScalarShl4(t *testing.T) {
	TfheScalarShl(t, FheUint4)
}

func TestTfheScalarShl8(t *testing.T) {
	TfheScalarShl(t, FheUint8)
}

func TestTfheScalarShl16(t *testing.T) {
	TfheScalarShl(t, FheUint16)
}

func TestTfheScalarShl32(t *testing.T) {
	TfheScalarShl(t, FheUint32)
}

func TestTfheScalarShl64(t *testing.T) {
	TfheScalarShl(t, FheUint64)
}

func TestTfheShr4(t *testing.T) {
	TfheShr(t, FheUint4)
}

func TestTfheShr8(t *testing.T) {
	TfheShr(t, FheUint8)
}

func TestTfheShr16(t *testing.T) {
	TfheShr(t, FheUint16)
}

func TestTfheShr32(t *testing.T) {
	TfheShr(t, FheUint32)
}

func TestTfheShr64(t *testing.T) {
	TfheShr(t, FheUint64)
}

func TestTfheScalarShr8(t *testing.T) {
	TfheScalarShr(t, FheUint8)
}

func TestTfheScalarShr16(t *testing.T) {
	TfheScalarShr(t, FheUint16)
}

func TestTfheScalarShr32(t *testing.T) {
	TfheScalarShr(t, FheUint32)
}

func TestTfheScalarShr64(t *testing.T) {
	TfheScalarShr(t, FheUint64)
}

func TestTfheRotl4(t *testing.T) {
	TfheRotl(t, FheUint4)
}

func TestTfheRotl8(t *testing.T) {
	TfheRotl(t, FheUint8)
}

func TestTfheRotl16(t *testing.T) {
	TfheRotl(t, FheUint16)
}

func TestTfheRotl32(t *testing.T) {
	TfheRotl(t, FheUint32)
}

func TestTfheRotl64(t *testing.T) {
	TfheRotl(t, FheUint64)
}

func TestTfheScalarRotl4(t *testing.T) {
	TfheScalarRotl(t, FheUint4)
}

func TestTfheScalarRotl8(t *testing.T) {
	TfheScalarRotl(t, FheUint8)
}

func TestTfheScalarRotl16(t *testing.T) {
	TfheScalarRotl(t, FheUint16)
}

func TestTfheScalarRotl32(t *testing.T) {
	TfheScalarRotl(t, FheUint32)
}

func TestTfheScalarRotl64(t *testing.T) {
	TfheScalarRotl(t, FheUint64)
}

func TestTfheRotr4(t *testing.T) {
	TfheRotr(t, FheUint4)
}

func TestTfheRotr8(t *testing.T) {
	TfheRotr(t, FheUint8)
}

func TestTfheRotr16(t *testing.T) {
	TfheRotr(t, FheUint16)
}

func TestTfheRotr32(t *testing.T) {
	TfheRotr(t, FheUint32)
}

func TestTfheRotr64(t *testing.T) {
	TfheRotr(t, FheUint64)
}

func TestTfheScalarRotr8(t *testing.T) {
	TfheScalarRotr(t, FheUint8)
}

func TestTfheScalarRotr16(t *testing.T) {
	TfheScalarRotr(t, FheUint16)
}

func TestTfheScalarRotr32(t *testing.T) {
	TfheScalarRotr(t, FheUint32)
}

func TestTfheScalarRotr64(t *testing.T) {
	TfheScalarRotr(t, FheUint64)
}

func TestTfheEq4(t *testing.T) {
	TfheEq(t, FheUint4)
}

func TestTfheEq8(t *testing.T) {
	TfheEq(t, FheUint8)
}

func TestTfheEq16(t *testing.T) {
	TfheEq(t, FheUint16)
}

func TestTfheEq32(t *testing.T) {
	TfheEq(t, FheUint32)
}

func TestTfheEq64(t *testing.T) {
	TfheEq(t, FheUint64)
}

func TestTfheEq160(t *testing.T) {
	TfheEq(t, FheUint160)
}

func TestTfheEq2048(t *testing.T) {
	TfheEq(t, FheUint2048)
}

func TestTfheScalarEq4(t *testing.T) {
	TfheScalarEq(t, FheUint4)
}

func TestTfheScalarEq8(t *testing.T) {
	TfheScalarEq(t, FheUint8)
}

func TestTfheScalarEq16(t *testing.T) {
	TfheScalarEq(t, FheUint16)
}

func TestTfheScalarEq32(t *testing.T) {
	TfheScalarEq(t, FheUint32)
}

func TestTfheScalarEq64(t *testing.T) {
	TfheScalarEq(t, FheUint64)
}

func TestTfheScalarEq160(t *testing.T) {
	TfheScalarEq(t, FheUint160)
}

func TestTfheNe4(t *testing.T) {
	TfheNe(t, FheUint8)
}

func TestTfheNe8(t *testing.T) {
	TfheNe(t, FheUint8)
}

func TestTfheNe16(t *testing.T) {
	TfheNe(t, FheUint16)
}

func TestTfheNe32(t *testing.T) {
	TfheNe(t, FheUint32)
}

func TestTfheNe64(t *testing.T) {
	TfheNe(t, FheUint64)
}

func TestTfheNe160(t *testing.T) {
	TfheNe(t, FheUint160)
}

func TestTfheNe2048(t *testing.T) {
	TfheNe(t, FheUint2048)
}

func TestTfheScalarNe4(t *testing.T) {
	TfheScalarNe(t, FheUint4)
}

func TestTfheScalarNe8(t *testing.T) {
	TfheScalarNe(t, FheUint8)
}

func TestTfheScalarNe16(t *testing.T) {
	TfheScalarNe(t, FheUint16)
}

func TestTfheScalarNe32(t *testing.T) {
	TfheScalarNe(t, FheUint32)
}

func TestTfheScalarNe64(t *testing.T) {
	TfheScalarNe(t, FheUint64)
}

func TestTfheScalarNe160(t *testing.T) {
	TfheScalarNe(t, FheUint160)
}

func TestTfheGe4(t *testing.T) {
	TfheGe(t, FheUint4)
}

func TestTfheGe8(t *testing.T) {
	TfheGe(t, FheUint8)
}

func TestTfheGe16(t *testing.T) {
	TfheGe(t, FheUint16)
}

func TestTfheGe32(t *testing.T) {
	TfheGe(t, FheUint32)
}

func TestTfheGe64(t *testing.T) {
	TfheGe(t, FheUint64)
}

func TestTfheScalarGe4(t *testing.T) {
	TfheScalarGe(t, FheUint4)
}

func TestTfheScalarGe8(t *testing.T) {
	TfheScalarGe(t, FheUint8)
}

func TestTfheScalarGe16(t *testing.T) {
	TfheScalarGe(t, FheUint16)
}

func TestTfheScalarGe32(t *testing.T) {
	TfheScalarGe(t, FheUint32)
}

func TestTfheScalarGe64(t *testing.T) {
	TfheScalarGe(t, FheUint64)
}

func TestTfheGt4(t *testing.T) {
	TfheGt(t, FheUint4)
}

func TestTfheGt8(t *testing.T) {
	TfheGt(t, FheUint8)
}

func TestTfheGt16(t *testing.T) {
	TfheGt(t, FheUint16)
}

func TestTfheGt32(t *testing.T) {
	TfheGt(t, FheUint32)
}

func TestTfheGt64(t *testing.T) {
	TfheGt(t, FheUint64)
}

func TestTfheScalarGt4(t *testing.T) {
	TfheScalarGt(t, FheUint4)
}

func TestTfheScalarGt8(t *testing.T) {
	TfheScalarGt(t, FheUint8)
}

func TestTfheScalarGt16(t *testing.T) {
	TfheScalarGt(t, FheUint16)
}

func TestTfheScalarGt32(t *testing.T) {
	TfheScalarGt(t, FheUint32)
}

func TestTfheScalarGt64(t *testing.T) {
	TfheScalarGt(t, FheUint64)
}

func TestTfheLe4(t *testing.T) {
	TfheLe(t, FheUint4)
}

func TestTfheLe8(t *testing.T) {
	TfheLe(t, FheUint8)
}

func TestTfheLe16(t *testing.T) {
	TfheLe(t, FheUint16)
}

func TestTfheLe32(t *testing.T) {
	TfheLe(t, FheUint32)
}

func TestTfheLe64(t *testing.T) {
	TfheLe(t, FheUint64)
}

func TestTfheScalarLe4(t *testing.T) {
	TfheScalarLe(t, FheUint4)
}

func TestTfheScalarLe8(t *testing.T) {
	TfheScalarLe(t, FheUint8)
}

func TestTfheScalarLe16(t *testing.T) {
	TfheScalarLe(t, FheUint16)
}

func TestTfheScalarLe32(t *testing.T) {
	TfheScalarLe(t, FheUint32)
}

func TestTfheScalarLe64(t *testing.T) {
	TfheScalarLe(t, FheUint64)
}

func TestTfheLt4(t *testing.T) {
	TfheLt(t, FheUint4)
}

func TestTfheLt8(t *testing.T) {
	TfheLt(t, FheUint8)
}

func TestTfheLt16(t *testing.T) {
	TfheLt(t, FheUint16)
}
func TestTfheLt32(t *testing.T) {
	TfheLt(t, FheUint32)
}
func TestTfheLt64(t *testing.T) {
	TfheLt(t, FheUint64)
}

func TestTfheScalarLt4(t *testing.T) {
	TfheScalarLt(t, FheUint4)
}

func TestTfheScalarLt8(t *testing.T) {
	TfheScalarLt(t, FheUint8)
}

func TestTfheScalarLt16(t *testing.T) {
	TfheScalarLt(t, FheUint16)
}

func TestTfheScalarLt32(t *testing.T) {
	TfheScalarLt(t, FheUint32)
}

func TestTfheScalarLt64(t *testing.T) {
	TfheScalarLt(t, FheUint64)
}

func TestTfheMin4(t *testing.T) {
	TfheMin(t, FheUint4)
}

func TestTfheMin8(t *testing.T) {
	TfheMin(t, FheUint8)
}

func TestTfheMin16(t *testing.T) {
	TfheMin(t, FheUint16)
}
func TestTfheMin32(t *testing.T) {
	TfheMin(t, FheUint32)
}
func TestTfheMin64(t *testing.T) {
	TfheMin(t, FheUint64)
}

func TestTfheScalarMin4(t *testing.T) {
	TfheScalarMin(t, FheUint4)
}

func TestTfheScalarMin8(t *testing.T) {
	TfheScalarMin(t, FheUint8)
}

func TestTfheScalarMin16(t *testing.T) {
	TfheScalarMin(t, FheUint16)
}

func TestTfheScalarMin32(t *testing.T) {
	TfheScalarMin(t, FheUint32)
}

func TestTfheScalarMin64(t *testing.T) {
	TfheScalarMin(t, FheUint64)
}

func TestTfheMax4(t *testing.T) {
	TfheMax(t, FheUint4)
}

func TestTfheMax8(t *testing.T) {
	TfheMax(t, FheUint8)
}

func TestTfheMax16(t *testing.T) {
	TfheMax(t, FheUint16)
}
func TestTfheMax32(t *testing.T) {
	TfheMax(t, FheUint32)
}
func TestTfheMax64(t *testing.T) {
	TfheMax(t, FheUint64)
}

func TestTfheScalarMax4(t *testing.T) {
	TfheScalarMax(t, FheUint4)
}

func TestTfheScalarMax8(t *testing.T) {
	TfheScalarMax(t, FheUint8)
}

func TestTfheScalarMax16(t *testing.T) {
	TfheScalarMax(t, FheUint16)
}

func TestTfheScalarMax32(t *testing.T) {
	TfheScalarMax(t, FheUint32)
}

func TestTfheScalarMax64(t *testing.T) {
	TfheScalarMax(t, FheUint64)
}

func TestTfheNeg4(t *testing.T) {
	TfheNeg(t, FheUint4)
}

func TestTfheNeg8(t *testing.T) {
	TfheNeg(t, FheUint8)
}

func TestTfheNeg16(t *testing.T) {
	TfheNeg(t, FheUint16)
}
func TestTfheNeg32(t *testing.T) {
	TfheNeg(t, FheUint32)
}
func TestTfheNeg64(t *testing.T) {
	TfheNeg(t, FheUint64)
}

func TestTfheNot4(t *testing.T) {
	TfheNot(t, FheUint8)
}

func TestTfheNot8(t *testing.T) {
	TfheNot(t, FheUint8)
}

func TestTfheNot16(t *testing.T) {
	TfheNot(t, FheUint16)
}
func TestTfheNot32(t *testing.T) {
	TfheNot(t, FheUint32)
}
func TestTfheNot64(t *testing.T) {
	TfheNot(t, FheUint64)
}

func TestTfheIfThenElse4(t *testing.T) {
	TfheIfThenElse(t, FheUint4)
}

func TestTfheIfThenElse8(t *testing.T) {
	TfheIfThenElse(t, FheUint8)
}

func TestTfheIfThenElse16(t *testing.T) {
	TfheIfThenElse(t, FheUint16)
}
func TestTfheIfThenElse32(t *testing.T) {
	TfheIfThenElse(t, FheUint32)
}
func TestTfheIfThenElse64(t *testing.T) {
	TfheIfThenElse(t, FheUint64)
}

func TestTfheIfThenElse160(t *testing.T) {
	TfheIfThenElse(t, FheUint160)
}

func TestTfhe4Cast8(t *testing.T) {
	TfheCast(t, FheUint4, FheUint8)
}

func TestTfhe4Cast16(t *testing.T) {
	TfheCast(t, FheUint4, FheUint16)
}

func TestTfhe4Cast32(t *testing.T) {
	TfheCast(t, FheUint4, FheUint32)
}

func TestTfhe4Cast64(t *testing.T) {
	TfheCast(t, FheUint4, FheUint64)
}

func TestTfhe8Cast4(t *testing.T) {
	TfheCast(t, FheUint8, FheUint4)
}

func TestTfhe8Cast16(t *testing.T) {
	TfheCast(t, FheUint4, FheUint16)
}

func TestTfhe8Cast32(t *testing.T) {
	TfheCast(t, FheUint8, FheUint32)
}

func TestTfhe8Cast64(t *testing.T) {
	TfheCast(t, FheUint8, FheUint64)
}

func TestTfhe16Cast4(t *testing.T) {
	TfheCast(t, FheUint16, FheUint4)
}

func TestTfhe16Cast8(t *testing.T) {
	TfheCast(t, FheUint16, FheUint8)
}

func TestTfhe16Cast32(t *testing.T) {
	TfheCast(t, FheUint16, FheUint32)
}

func TestTfhe16Cast64(t *testing.T) {
	TfheCast(t, FheUint16, FheUint64)
}

func TestTfhe32Cast4(t *testing.T) {
	TfheCast(t, FheUint32, FheUint4)
}

func TestTfhe32Cast8(t *testing.T) {
	TfheCast(t, FheUint32, FheUint8)
}

func TestTfhe32Cast16(t *testing.T) {
	TfheCast(t, FheUint32, FheUint16)
}

func TestTfhe32Cast64(t *testing.T) {
	TfheCast(t, FheUint32, FheUint64)
}

func TestTfhe64Cast4(t *testing.T) {
	TfheCast(t, FheUint64, FheUint4)
}

func TestTfhe64Cast8(t *testing.T) {
	TfheCast(t, FheUint64, FheUint8)
}

func TestTfhe64Cast16(t *testing.T) {
	TfheCast(t, FheUint64, FheUint16)
}

func TestTfhe64Cast32(t *testing.T) {
	TfheCast(t, FheUint64, FheUint32)
}

func TestTfheEqArrayEqual4(t *testing.T) {
	TfheEqArrayEqual(t, FheUint4)
}

func TestTfheEqArrayEqual8(t *testing.T) {
	TfheEqArrayEqual(t, FheUint8)
}

func TestTfheEqArrayEqual16(t *testing.T) {
	TfheEqArrayEqual(t, FheUint16)
}

func TestTfheEqArrayEqual32(t *testing.T) {
	TfheEqArrayEqual(t, FheUint32)
}

func TestTfheEqArrayEqual64(t *testing.T) {
	TfheEqArrayEqual(t, FheUint64)
}

func TestTfheEqArrayCompareToSelf4(t *testing.T) {
	TfheEqArrayCompareToSelf(t, FheUint4)
}

func TestTfheEqArrayCompareToSelf8(t *testing.T) {
	TfheEqArrayCompareToSelf(t, FheUint8)
}

func TestTfheEqArrayCompareToSelf16(t *testing.T) {
	TfheEqArrayCompareToSelf(t, FheUint16)
}

func TestTfheEqArrayCompareToSelf32(t *testing.T) {
	TfheEqArrayCompareToSelf(t, FheUint32)
}

func TestTfheEqArrayCompareToSelf64(t *testing.T) {
	TfheEqArrayCompareToSelf(t, FheUint64)
}

func TestTfheEqArrayNotEqualSameLen4(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint4)
}

func TestTfheEqArrayNotEqualSameLen8(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint8)
}

func TestTfheEqArrayNotEqualSameLen16(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint16)
}

func TestTfheEqArrayNotEqualSameLen32(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint32)
}

func TestTfheEqArrayNotEqualSameLen64(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint64)
}

func TestTfheEqArrayNotEqualDifferentLen4(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint4)
}

func TestTfheEqArrayNotEqualDifferentLen8(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint8)
}

func TestTfheEqArrayNotEqualDifferentLen16(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint16)
}

func TestTfheEqArrayNotEqualDifferentLen32(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint32)
}

func TestTfheEqArrayNotEqualDifferentLen64(t *testing.T) {
	TfheEqArrayNotEqualSameLen(t, FheUint64)
}
