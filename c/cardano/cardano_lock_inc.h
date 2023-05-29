#include "ckb_consts.h"
#include "stdio.h"
#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_auth_sim.h"
#else

#include "ckb_syscalls.h"
#endif

//
#include "nanocbor.h"

#ifndef CHECK
#define CHECK(code)      \
    do {                 \
        if (code != 0) { \
            err = code;  \
            goto exit;   \
        }                \
    } while (0)
#endif

#ifndef CHECK2
#define CHECK2(cond, code) \
    do {                   \
        if (!(cond)) {     \
            err = code;    \
            goto exit;     \
        }                  \
    } while (0)
#endif  // CHECK2

#define CARDANO_LOCK_PUBKEY_SIZE 32
#define CARDANO_LOCK_SIGNATURE_SIZE 64
#define CARDANO_LOCK_PAYLOAD_SIZE 32
#define CARDANO_LOCK_BLAKE2B_BLOCK_SIZE 32

enum CardanoErrorCodeType {
    CardanoSuccess = 0,
    CardanoErr_InvalidARG = 201,
    CardanoErr_CBORParse,
    CardanoErr_CBORType,
    CardanoErr_InvaildSignMsgLen,
    CardanoErr_InvaildPubKeyLen,
    CardanoErr_InvaildSignLen,
};

typedef struct {
    uint8_t sign_msg[CARDANO_LOCK_PAYLOAD_SIZE];
    uint8_t public_key[CARDANO_LOCK_PUBKEY_SIZE];
    uint8_t signature[CARDANO_LOCK_SIGNATURE_SIZE];
} CardanoSignatureData;

int get_cardano_sign_data(uint8_t *data, size_t data_len,
                          CardanoSignatureData *output) {
    int err = CardanoSuccess;

    nanocbor_value_t root_node = {0};
    nanocbor_decoder_init(&root_node, data, data_len);

    CHECK2(nanocbor_get_type(&root_node) == NANOCBOR_TYPE_ARR,
           CardanoErr_CBORType);
    nanocbor_value_t root_array_node;
    CHECK2(nanocbor_enter_array(&root_node, &root_array_node) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    nanocbor_value_t sign_data_node;
    CHECK2(
        nanocbor_enter_array(&root_array_node, &sign_data_node) == NANOCBOR_OK,
        CardanoErr_CBORParse);

    uint8_t *sign_msg_ptr = NULL;
    size_t sign_msg_ptr_len = 0;
    CHECK2(nanocbor_get_type(&sign_data_node) == NANOCBOR_TYPE_BSTR,
           CardanoErr_CBORType);
    CHECK2(nanocbor_get_bstr(&sign_data_node, (const uint8_t **)&sign_msg_ptr,
                             &sign_msg_ptr_len) == NANOCBOR_OK,
           CardanoErr_CBORParse);
    CHECK2(sign_msg_ptr_len == CARDANO_LOCK_PAYLOAD_SIZE,
           CardanoErr_InvaildSignMsgLen);
    memcpy(output->sign_msg, sign_msg_ptr, sign_msg_ptr_len);

    uint8_t *pubkey_ptr = NULL;
    size_t pubkey_ptr_len = 0;
    CHECK2(nanocbor_get_type(&sign_data_node) == NANOCBOR_TYPE_BSTR,
           CardanoErr_CBORType);
    CHECK2(nanocbor_get_bstr(&sign_data_node, (const uint8_t **)&pubkey_ptr,
                             &pubkey_ptr_len) == NANOCBOR_OK,
           CardanoErr_CBORParse);
    CHECK2(pubkey_ptr_len == CARDANO_LOCK_PUBKEY_SIZE,
           CardanoErr_InvaildPubKeyLen);
    memcpy(output->public_key, pubkey_ptr, pubkey_ptr_len);

    nanocbor_skip(&root_array_node);
    nanocbor_skip(&root_array_node);

    uint8_t *sign_ptr = NULL;
    size_t sign_ptr_len = 0;
    CHECK2(nanocbor_get_type(&root_array_node) == NANOCBOR_TYPE_BSTR,
           CardanoErr_CBORType);
    CHECK2(nanocbor_get_bstr(&root_array_node, (const uint8_t **)&sign_ptr,
                             &sign_ptr_len) == NANOCBOR_OK,
           CardanoErr_CBORParse);
    CHECK2(sign_ptr_len == CARDANO_LOCK_SIGNATURE_SIZE,
           CardanoErr_InvaildSignLen);
    memcpy(output->signature, sign_ptr, sign_ptr_len);

    memset(sign_ptr, 0, sign_ptr_len);
exit:
    return err;
};

int get_cardano_custom(const uint8_t *data, size_t data_len,
                       nanocbor_value_t *custom_node) {
    int err = CardanoSuccess;

    nanocbor_value_t root_node = {0};
    nanocbor_decoder_init(&root_node, data, data_len);

    CHECK2(nanocbor_get_type(&root_node) == NANOCBOR_TYPE_ARR,
           CardanoErr_CBORType);
    nanocbor_value_t root_array_node;
    CHECK2(nanocbor_enter_array(&root_node, &root_array_node) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    nanocbor_skip(&root_array_node);

    memcpy(custom_node, &root_array_node, sizeof(root_array_node));
exit:
    return err;
}
