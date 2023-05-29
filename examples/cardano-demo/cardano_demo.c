// a demo to use "auth" lib
// script args: <21 bytes auth> <32 bytes code hash> <1 byte hash type> <1 byte
// entry category> see `CkbEntryType`
//
// witness lock: signature

#include "blake2b.h"
#include "blockchain.h"
#include "ckb_auth.h"
#include "ckb_consts.h"
#include "ckb_syscalls.h"

//
#include "cardano/cardano_lock_inc.h"

#define BLAKE2B_BLOCK_SIZE 32
#define TEMP_SIZE 32768
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768

#define ONE_BATCH_SIZE 32768

static int extract_witness_lock(uint8_t *witness, uint64_t len,
                                mol_seg_t *lock_bytes_seg) {
    if (len < 20) {
        return CKB_INVALID_DATA;
    }
    uint32_t lock_length = *((uint32_t *)(&witness[16]));
    if (len < 20 + lock_length) {
        return CKB_INVALID_DATA;
    } else {
        lock_bytes_seg->ptr = &witness[20];
        lock_bytes_seg->size = lock_length;
    }
    return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source, bool hash_length) {
    uint8_t temp[ONE_BATCH_SIZE];
    uint64_t len = ONE_BATCH_SIZE;
    int ret = ckb_load_witness(temp, &len, start, index, source);
    if (ret != CKB_SUCCESS) {
        return ret;
    }
    if (hash_length) {
        blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
    }
    uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
    blake2b_update(ctx, temp, offset);
    while (offset < len) {
        uint64_t current_len = ONE_BATCH_SIZE;
        ret =
            ckb_load_witness(temp, &current_len, start + offset, index, source);
        if (ret != CKB_SUCCESS) {
            return ret;
        }
        uint64_t current_read =
            (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
        blake2b_update(ctx, temp, current_read);
        offset += current_read;
    }
    return CKB_SUCCESS;
}

int generate_sighash_all(uint8_t *msg, size_t msg_len) {
    int ret;
    uint64_t len = 0;
    unsigned char temp[MAX_WITNESS_SIZE];
    uint64_t read_len = MAX_WITNESS_SIZE;
    uint64_t witness_len = MAX_WITNESS_SIZE;

    if (msg_len < BLAKE2B_BLOCK_SIZE) {
        return CKB_INVALID_DATA;
    }

    /* Load witness of first input */
    ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
        return CKB_INVALID_DATA;
    }
    witness_len = read_len;
    if (read_len > MAX_WITNESS_SIZE) {
        read_len = MAX_WITNESS_SIZE;
    }

    /* load signature */
    mol_seg_t lock_bytes_seg;
    ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
    if (ret != 0) {
        return CKB_INVALID_DATA;
    }

    /* Load tx hash */
    unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
    len = BLAKE2B_BLOCK_SIZE;
    ret = ckb_load_tx_hash(tx_hash, &len, 0);
    if (ret != CKB_SUCCESS) {
        return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
        return CKB_INVALID_DATA;
    }

    /* Prepare sign message */
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

    /* Clear lock field to zero, then digest the first witness
     * lock_bytes_seg.ptr actually points to the memory in temp buffer
     * */
    memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
    blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
    blake2b_update(&blake2b_ctx, temp, read_len);

    // remaining of first witness
    if (read_len < witness_len) {
        ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                    CKB_SOURCE_GROUP_INPUT, false);
        if (ret != CKB_SUCCESS) {
            return CKB_INVALID_DATA;
        }
    }

    // Digest same group witnesses
    size_t i = 1;
    while (1) {
        ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT,
                                    true);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (ret != CKB_SUCCESS) {
            return CKB_INVALID_DATA;
        }
        i += 1;
    }

    // Digest witnesses that not covered by inputs
    i = (size_t)ckb_calculate_inputs_len();
    while (1) {
        ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
        if (ret == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (ret != CKB_SUCCESS) {
            return CKB_INVALID_DATA;
        }
        i += 1;
    }

    blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);

    return 0;
}

enum {
    CardanoDemo_ParseNanocbor = 151,
    CardanoDemo_FixedVal,
    CardanoDemo_LockHash,
    CardanoDemo_LockHashLen,
    CardanoDemo_InputCapacity,
    CardanoDemo_InputCapacityLen,
    CardanoDemo_OutputCapacity,
    CardanoDemo_OutputCapacityLen,
} CardanoDemoErr;

int check_costom_data(const uint8_t *data, size_t data_len) {
    int err = 0;

    nanocbor_value_t custom_node;
    CHECK2(get_cardano_custom(data, data_len, &custom_node) == CardanoSuccess,
           CardanoDemo_ParseNanocbor);

    nanocbor_value_t custom_array_node;
    CHECK2(nanocbor_get_type(&custom_node) == NANOCBOR_TYPE_ARR,
           CardanoDemo_ParseNanocbor);
    CHECK2(
        nanocbor_enter_array(&custom_node, &custom_array_node) == NANOCBOR_OK,
        CardanoDemo_ParseNanocbor);

    int32_t custom_data_1 = 0;
    CHECK2(nanocbor_get_type(&custom_array_node) == NANOCBOR_TYPE_UINT,
           CardanoDemo_ParseNanocbor);
    nanocbor_get_int32(&custom_array_node, &custom_data_1);

    CHECK2(custom_data_1 == 0x123123, CardanoDemo_FixedVal);

    // Lock hash
    uint8_t lock_hash[32];
    uint64_t len = 32;
    CHECK(ckb_load_cell_by_field(lock_hash, &len, 0, 0, CKB_SOURCE_INPUT,
                                 CKB_CELL_FIELD_LOCK_HASH));
    uint8_t *lock_hash_ptr = NULL;
    size_t lock_hash_len = 0;
    CHECK2(
        (nanocbor_get_bstr(&custom_array_node, (const uint8_t **)&lock_hash_ptr,
                           &lock_hash_len)) == NANOCBOR_OK,
        CardanoDemo_ParseNanocbor);

    CHECK2(lock_hash_len == 32, CardanoDemo_LockHashLen);
    CHECK2(memcmp(lock_hash_ptr, lock_hash, 32) == 0, CardanoDemo_LockHash);

    // Input capacity
    uint8_t input_capacity[8];
    len = sizeof(input_capacity);
    CHECK(ckb_load_cell_by_field(input_capacity, &len, 0, 0, CKB_SOURCE_INPUT,
                                 CKB_CELL_FIELD_CAPACITY));

    uint8_t *input_capacity_ptr = NULL;
    uint64_t input_capacity_len = 0;
    CHECK2((nanocbor_get_bstr(&custom_array_node,
                              (const uint8_t **)&input_capacity_ptr,
                              &input_capacity_len)) == NANOCBOR_OK,
           CardanoDemo_ParseNanocbor);
    CHECK2(input_capacity_len == 8, CardanoDemo_InputCapacityLen);
    CHECK2(len == input_capacity_len, CardanoDemo_InputCapacityLen);
    CHECK2(memcmp(input_capacity, input_capacity_ptr, 8) == 0,
           CardanoDemo_InputCapacity);

    // Output capacity
    uint8_t output_capacity[8];
    len = sizeof(output_capacity);
    CHECK(ckb_load_cell_by_field(output_capacity, &len, 0, 0, CKB_SOURCE_OUTPUT,
                                 CKB_CELL_FIELD_CAPACITY));

    uint8_t *output_capacity_ptr = NULL;
    uint64_t output_capacity_len = 0;
    CHECK2((nanocbor_get_bstr(&custom_array_node,
                              (const uint8_t **)&output_capacity_ptr,
                              &output_capacity_len)) == NANOCBOR_OK,
           CardanoDemo_ParseNanocbor);
    CHECK2(output_capacity_len == 8, CardanoDemo_OutputCapacityLen);
    CHECK2(len == output_capacity_len, CardanoDemo_OutputCapacityLen);
    CHECK2(memcmp(output_capacity, output_capacity_ptr, 8) == 0,
           CardanoDemo_OutputCapacity);

exit:
    return err;
}

int main() {
    int ret;
    uint64_t len = 0;
    unsigned char temp[TEMP_SIZE];

    unsigned char script[SCRIPT_SIZE];
    len = SCRIPT_SIZE;
    ret = ckb_load_script(script, &len, 0);
    if (ret != CKB_SUCCESS) {
        return CKB_INVALID_DATA;
    }
    if (len > SCRIPT_SIZE) {
        return CKB_INVALID_DATA;
    }
    mol_seg_t script_seg;
    script_seg.ptr = (uint8_t *)script;
    script_seg.size = len;

    if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
        return CKB_INVALID_DATA;
    }

    mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
    mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
    if (args_bytes_seg.size != (21 + 32 + 1 + 1)) {
        return CKB_INVALID_DATA;
    }

    // Load the first witness, or the witness of the same index as the first
    // input using current script.
    uint64_t witness_len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
    if (ret != CKB_SUCCESS) {
        return CKB_INVALID_DATA;
    }

    mol_seg_t lock_bytes_seg;
    ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
    if (ret != 0) {
        return CKB_INVALID_DATA;
    }
    uint8_t msg32[32];
    ret = generate_sighash_all(msg32, 32);
    if (ret != 0) return CKB_INVALID_DATA;

    CkbEntryType entry;
    memcpy(entry.code_hash, args_bytes_seg.ptr + 21, 32);
    entry.hash_type = *(args_bytes_seg.ptr + 21 + 32);
    entry.entry_category = *(args_bytes_seg.ptr + 21 + 32 + 1);

    CkbAuthType auth;
    auth.algorithm_id = *args_bytes_seg.ptr;
    memcpy(auth.content, args_bytes_seg.ptr + 1, 20);

    ret =
        ckb_auth(&entry, &auth, lock_bytes_seg.ptr, lock_bytes_seg.size, msg32);
    if (ret) return ret;

    // Do some custom checks here
    return check_costom_data(lock_bytes_seg.ptr, lock_bytes_seg.size);
}
