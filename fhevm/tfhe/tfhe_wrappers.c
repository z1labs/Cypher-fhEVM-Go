#include "tfhe_wrappers.h"

FhevmKeys generate_fhevm_keys(){
	ConfigBuilder* builder;
	Config *config;
	ClientKey *cks;
	ServerKey *sks;
	CompactPublicKey *pks;

	int r;
	r = config_builder_default(&builder);
	assert(r == 0);
	r = config_builder_use_custom_parameters(&builder, SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
	assert(r == 0);
	r = config_builder_build(builder, &config);
	assert(r == 0);
	r = generate_keys(config, &cks, &sks);
	assert(r == 0);
	r = compact_public_key_new(cks, &pks);
	assert(r == 0);

	FhevmKeys keys = {sks, cks, pks};
	return keys;
}

int serialize_compact_public_key(void *pks, DynamicBuffer* out) {
	return compact_public_key_serialize(pks, out);
}

void* deserialize_server_key(DynamicBufferView in) {
	ServerKey* sks = NULL;
	const int r = server_key_deserialize(in, &sks);
	assert(r == 0);
	return sks;
}

void* deserialize_client_key(DynamicBufferView in) {
	ClientKey* cks = NULL;
	const int r = client_key_deserialize(in, &cks);
	assert(r == 0);
	return cks;
}

void* deserialize_compact_public_key(DynamicBufferView in) {
	CompactPublicKey* pks = NULL;
	const int r = compact_public_key_deserialize(in, &pks);
	assert(r == 0);
	return pks;
}

void checked_set_server_key(void *sks) {
	const int r = set_server_key(sks);
	assert(r == 0);
}

void* cast_4_bool(void* ct, void* sks) {
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_ne(ct, 0, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_bool_4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_cast_into_fhe_uint4(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_8_bool(void* ct, void* sks) {
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ne(ct, 0, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_bool_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_bool_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_bool_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_bool_64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_cast_into_fhe_uint64(ct, &result);
	if(r != 0) return NULL;
	return result;
}

int serialize_fhe_bool(void *ct, DynamicBuffer* out) {
	return fhe_bool_serialize(ct, out);
}

void* deserialize_fhe_bool(DynamicBufferView in) {
	FheBool* ct = NULL;
	const int r = fhe_bool_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_bool(DynamicBufferView in) {
	CompactFheBoolList* list = NULL;
	FheBool* ct = NULL;

	int r = compact_fhe_bool_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_bool_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_bool_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_bool_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_bool_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint4(void *ct, DynamicBuffer* out) {
	return fhe_uint4_serialize(ct, out);
}

void* deserialize_fhe_uint4(DynamicBufferView in) {
	FheUint4* ct = NULL;
	const int r = fhe_uint4_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint4(DynamicBufferView in) {
	CompactFheUint4List* list = NULL;
	FheUint4* ct = NULL;

	int r = compact_fhe_uint4_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint4_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint4_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint4_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint4_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint8(void *ct, DynamicBuffer* out) {
	return fhe_uint8_serialize(ct, out);
}

void* deserialize_fhe_uint8(DynamicBufferView in) {
	FheUint8* ct = NULL;
	const int r = fhe_uint8_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint8(DynamicBufferView in) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint8_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint8_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint16(void *ct, DynamicBuffer* out) {
	return fhe_uint16_serialize(ct, out);
}

void* deserialize_fhe_uint16(DynamicBufferView in) {
	FheUint16* ct = NULL;
	const int r = fhe_uint16_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint16(DynamicBufferView in) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint16_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint16_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint32(void *ct, DynamicBuffer* out) {
	return fhe_uint32_serialize(ct, out);
}

void* deserialize_fhe_uint32(DynamicBufferView in) {
	FheUint32* ct = NULL;
	const int r = fhe_uint32_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint32(DynamicBufferView in) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint32_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint32_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);
	return ct;
}

int serialize_fhe_uint64(void *ct, DynamicBuffer* out) {
	return fhe_uint64_serialize(ct, out);
}

void* deserialize_fhe_uint64(DynamicBufferView in) {
	FheUint64* ct = NULL;
	const int r = fhe_uint64_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint64(DynamicBufferView in) {
	CompactFheUint64List* list = NULL;
	FheUint64* ct = NULL;

	int r = compact_fhe_uint64_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint64_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint64_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint64_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint64_list_destroy(list);
	assert(r == 0);
	return ct;
}


int serialize_fhe_uint160(void *ct, DynamicBuffer* out) {
	return fhe_uint160_serialize(ct, out);
}

void* deserialize_fhe_uint160(DynamicBufferView in) {
	FheUint160* ct = NULL;
	const int r = fhe_uint160_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

int serialize_fhe_uint2048(void *ct, DynamicBuffer* out) {
	return fhe_uint2048_serialize(ct, out);
}

void* deserialize_fhe_uint2048(DynamicBufferView in) {
	FheUint2048* ct = NULL;
	const int r = fhe_uint2048_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint160(DynamicBufferView in) {
	CompactFheUint160List* list = NULL;
	FheUint160* ct = NULL;

	int r = compact_fhe_uint160_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint160_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint160_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint160_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint160_list_destroy(list);
	assert(r == 0);
	return ct;
}

void* deserialize_compact_fhe_uint2048(DynamicBufferView in) {
	CompactFheUint2048List* list = NULL;
	FheUint2048* ct = NULL;

	int r = compact_fhe_uint2048_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint2048_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint2048_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint2048_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint2048_list_destroy(list);
	assert(r == 0);
	return ct;
}

void destroy_fhe_bool(void* ct) {
	const int r = fhe_bool_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint4(void* ct) {
	const int r = fhe_uint4_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint8(void* ct) {
	const int r = fhe_uint8_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint16(void* ct) {
	const int r = fhe_uint16_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint32(void* ct) {
	const int r = fhe_uint32_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint64(void* ct) {
	const int r = fhe_uint64_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint160(void* ct) {
	const int r = fhe_uint160_destroy(ct);
	assert(r == 0);
}

void destroy_fhe_uint2048(void* ct) {
	const int r = fhe_uint2048_destroy(ct);
	assert(r == 0);
}

void* add_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* add_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* add_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* add_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* add_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_add(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_add_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_add(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* sub_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_sub(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_sub_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_sub(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* mul_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_mul(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_mul_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_mul(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_div_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_div(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rem_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_rem(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_bool(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitand_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_bitand(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_bool(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitor_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_bitor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_bool(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* bitxor_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_bitxor(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shl_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_shl(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shl_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_shl(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* shr_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_shr(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_shr_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_shr(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotl_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_rotate_left(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotl_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_rotate_left(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotl_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_rotate_left(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotl_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_rotate_left(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotl_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_rotate_left(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotl_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_rotate_left(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotl_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_rotate_left(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotl_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_rotate_left(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotl_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_rotate_left(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotl_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_rotate_left(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotr_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_rotate_right(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotr_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_rotate_right(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotr_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_rotate_right(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotr_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_rotate_right(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* rotr_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_rotate_right(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotr_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_rotate_right(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotr_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_rotate_right(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotr_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_rotate_right(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotr_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_rotate_right(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_rotr_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_rotate_right(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint160(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_uint2048(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint2048_eq(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint160(void* ct, struct U256 pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_eq_fhe_uint2048(void* ct, struct U2048 pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint2048_scalar_eq(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_array_uint4(void* ct1, size_t ct1_len, void* ct2, size_t ct2_len, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_array_eq(ct1, ct1_len, ct2, ct2_len, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_array_uint8(void* ct1, size_t ct1_len, void* ct2, size_t ct2_len, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_array_eq(ct1, ct1_len, ct2, ct2_len, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_array_uint16(void* ct1, size_t ct1_len, void* ct2, size_t ct2_len, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_array_eq(ct1, ct1_len, ct2, ct2_len, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_array_uint32(void* ct1, size_t ct1_len, void* ct2, size_t ct2_len, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_array_eq(ct1, ct1_len, ct2, ct2_len, &result);
	if(r != 0) return NULL;
	return result;
}

void* eq_fhe_array_uint64(void* ct1, size_t ct1_len, void* ct2, size_t ct2_len, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_array_eq(ct1, ct1_len, ct2, ct2_len, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint160(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ne_fhe_uint2048(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint2048_ne(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint160(void* ct, struct U256 pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ne_fhe_uint2048(void* ct, struct U2048 pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint2048_scalar_ne(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* ge_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_ge(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_ge_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_ge(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* gt_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_gt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_gt_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_gt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* le_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_le(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_le_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_le(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* lt_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_lt(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_lt_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_lt(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* min_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_min(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_min_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_min(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint4(void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* max_fhe_uint64(void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_max(ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint4(void* ct, uint8_t pt, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* scalar_max_fhe_uint64(void* ct, uint64_t pt, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_scalar_max(ct, pt, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* neg_fhe_uint64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_neg(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_bool(void* ct, void* sks) {
	FheBool* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_bool_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* not_fhe_uint64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_not(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* if_then_else_fhe_uint4(void* condition, void* ct1, void* ct2, void* sks)
{
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_if_then_else(condition, ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* if_then_else_fhe_uint8(void* condition, void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_if_then_else(condition, ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* if_then_else_fhe_uint16(void* condition, void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_if_then_else(condition, ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* if_then_else_fhe_uint32(void* condition, void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_if_then_else(condition, ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* if_then_else_fhe_uint64(void* condition, void* ct1, void* ct2, void* sks)
{
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_if_then_else(condition, ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

void* if_then_else_fhe_uint160(void* condition, void* ct1, void* ct2, void* sks)
{
	FheUint160* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_if_then_else(condition, ct1, ct2, &result);
	if(r != 0) return NULL;
	return result;
}

int decrypt_fhe_bool(void* cks, void* ct, bool* res)
{
	*res = false;
	return fhe_bool_decrypt(ct, cks, res);
}

int decrypt_fhe_uint4(void* cks, void* ct, uint8_t* res)
{
	*res = 0;
	return fhe_uint4_decrypt(ct, cks, res);
}

int decrypt_fhe_uint8(void* cks, void* ct, uint8_t* res)
{
	*res = 0;
	return fhe_uint8_decrypt(ct, cks, res);
}

int decrypt_fhe_uint16(void* cks, void* ct, uint16_t* res)
{
	*res = 0;
	return fhe_uint16_decrypt(ct, cks, res);
}

int decrypt_fhe_uint32(void* cks, void* ct, uint32_t* res)
{
	*res = 0;
	return fhe_uint32_decrypt(ct, cks, res);
}

int decrypt_fhe_uint64(void* cks, void* ct, uint64_t* res)
{
	*res = 0;
	return fhe_uint64_decrypt(ct, cks, res);
}

int decrypt_fhe_uint160(void* cks, void* ct, struct U256 *res)
{
	return fhe_uint160_decrypt(ct, cks, res);
}

int decrypt_fhe_uint2048(void* cks, void* ct, struct U2048* res) {
	return fhe_uint2048_decrypt(ct, cks, res);
}

void* public_key_encrypt_fhe_bool(void* pks, bool value) {
	CompactFheBoolList* list = NULL;
	FheBool* ct = NULL;

	int r = compact_fhe_bool_list_try_encrypt_with_compact_public_key_bool(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_bool_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_bool_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint4(void* pks, uint8_t value) {
	CompactFheUint4List* list = NULL;
	FheUint4* ct = NULL;

	int r = compact_fhe_uint4_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint4_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint4_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint8(void* pks, uint8_t value) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint16(void* pks, uint16_t value) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint32(void* pks, uint32_t value) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint64(void* pks, uint64_t value) {
	CompactFheUint64List* list = NULL;
	FheUint64* ct = NULL;

	int r = compact_fhe_uint64_list_try_encrypt_with_compact_public_key_u64(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint64_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint64_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint160(void* pks, struct U256 *value) {
	CompactFheUint160List* list = NULL;
	FheUint160* ct = NULL;

	int r = compact_fhe_uint160_list_try_encrypt_with_compact_public_key_u256(value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint160_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint160_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint2048(void* pks, struct U2048 *value) {
	FheUint2048* ct = NULL;

	int r = fhe_uint2048_try_encrypt_with_compact_public_key_u2048(*value, pks, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_bool(void* sks, bool value) {
	FheBool* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_bool_try_encrypt_trivial_bool(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint4(void* sks, uint8_t value) {
	FheUint4* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint4_try_encrypt_trivial_u8(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint8(void* sks, uint8_t value) {
	FheUint8* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint8_try_encrypt_trivial_u8(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint16(void* sks, uint16_t value) {
	FheUint16* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint16_try_encrypt_trivial_u16(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint32(void* sks, uint32_t value) {
	FheUint32* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint32_try_encrypt_trivial_u32(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint64(void* sks, uint64_t value) {
	FheUint64* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint64_try_encrypt_trivial_u64(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint160(void* sks, struct U256* value) {
	FheUint160* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint160_try_encrypt_trivial_u256(*value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint2048(void* sks, struct U2048* value) {
	FheUint2048* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint2048_try_encrypt_trivial_u2048(*value, &ct);
  	assert(r == 0);

	return ct;
}

void public_key_encrypt_and_serialize_fhe_bool_list(void* pks, bool value, DynamicBuffer* out) {
	CompactFheBoolList* list = NULL;

	int r = compact_fhe_bool_list_try_encrypt_with_compact_public_key_bool(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_bool_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_bool_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint4_list(void* pks, uint8_t value, DynamicBuffer* out) {
	CompactFheUint4List* list = NULL;

	int r = compact_fhe_uint4_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint4_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint4_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint8_list(void* pks, uint8_t value, DynamicBuffer* out) {
	CompactFheUint8List* list = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint16_list(void* pks, uint16_t value, DynamicBuffer* out) {
	CompactFheUint16List* list = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint32_list(void* pks, uint32_t value, DynamicBuffer* out) {
	CompactFheUint32List* list = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint64_list(void* pks, uint64_t value, DynamicBuffer* out) {
	CompactFheUint64List* list = NULL;

	int r = compact_fhe_uint64_list_try_encrypt_with_compact_public_key_u64(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint64_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint64_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint160_list(void* pks, struct U256 *value, DynamicBuffer* out) {
	CompactFheUint160List* list = NULL;
	FheUint160* ct = NULL;

	int r = compact_fhe_uint160_list_try_encrypt_with_compact_public_key_u256(value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint160_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint160_list_destroy(list);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint2048_list(void* pks, struct U2048 *value, DynamicBuffer* out) {
	CompactFheUint2048List* list = NULL;
	FheUint2048* ct = NULL;

	int r = compact_fhe_uint2048_list_try_encrypt_with_compact_public_key_u2048(value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint2048_list_serialize(list, out);
	assert(r == 0);

	r = compact_fhe_uint2048_list_destroy(list);
	assert(r == 0);
}

void* cast_4_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_4_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_4_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_4_64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint4_cast_into_fhe_uint64(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_8_4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint4(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_8_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_8_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_8_64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint64(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_16_4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint4(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_16_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_16_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_16_64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint64(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_32_4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint4(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_32_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_32_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_32_64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint64(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_64_4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_cast_into_fhe_uint4(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_64_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_64_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_64_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint64_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_160_4(void* ct, void* sks) {
	FheUint4* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_cast_into_fhe_uint4(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_160_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_cast_into_fhe_uint8(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_160_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_cast_into_fhe_uint16(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_160_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_cast_into_fhe_uint32(ct, &result);
	if(r != 0) return NULL;
	return result;
}

void* cast_160_64(void* ct, void* sks) {
	FheUint64* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint160_cast_into_fhe_uint64(ct, &result);
	if(r != 0) return NULL;
	return result;
}
