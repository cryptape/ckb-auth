#include "ckb_consts.h"
#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_auth_sim.h"
#else
#define CKB_C_STDLIB_PRINTF
#include <stdio.h>
#include "ckb_syscalls.h"
#endif

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif

#include "cardano_lock_mol.h"
#include "cardano_lock_mol2.h"
#include "molecule/molecule_reader.h"

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
    ERROR_INVALID_SIGN = 201,
    ERROR_AUTH_ARGUMENTS_LEN,
    ERROR_AUTH_SYSCALL,
    ERROR_AUTH_ENCODING,
    ERROR_ENCODING,
    ERROR_GENERATE_NEW_MSG,
    ERROR_LOAD_SCRIPT,
    ERROR_LOAD_WITNESS,
    ERROR_UNSUPPORTED_ARGS,
    ERROR_ARGS_LENGTH,
    ERROR_CONVERT_MESSAGE,
    ERROR_PAYLOAD,
    ERROR_VERIFY,
    ERROR_PUBKEY,
};

int get_cardano_witness_data(const uint8_t *data, size_t data_len,
                             uint8_t *pubkey, uint8_t *signature,
                             mol_seg_t *sig_structure) {
    int err = 0;
    mol_seg_t cardano_data = {(uint8_t *)data, data_len};
    mol_seg_t c_pubkey = MolReader_CardanoWitnessLock_get_pubkey(&cardano_data);
    CHECK2(c_pubkey.size == CARDANO_LOCK_PUBKEY_SIZE, ERROR_INVALID_SIGN);
    memcpy(pubkey, c_pubkey.ptr, CARDANO_LOCK_PUBKEY_SIZE);

    mol_seg_t c_sign =
        MolReader_CardanoWitnessLock_get_signature(&cardano_data);
    CHECK2(c_sign.size == CARDANO_LOCK_SIGNATURE_SIZE, ERROR_INVALID_SIGN);
    memcpy(signature, c_sign.ptr, CARDANO_LOCK_SIGNATURE_SIZE);

    mol_seg_t c_sig_structure =
        MolReader_CardanoWitnessLock_get_sig_structure(&cardano_data);
    *sig_structure = MolReader_Bytes_raw_bytes(&c_sig_structure);
    CHECK2(sig_structure->size != 0, ERROR_INVALID_SIGN);

exit:
    return err;
}

int get_cardano_payload(const uint8_t *new_msg, size_t len, uint8_t *payload) {
    int err = 0;
    nanocbor_value_t n_val = {0};
    nanocbor_decoder_init(&n_val, new_msg, len);

    int val_type = nanocbor_get_type(&n_val);
    CHECK2(val_type == NANOCBOR_TYPE_ARR, ERROR_PAYLOAD);

    nanocbor_value_t n_array;
    err = nanocbor_enter_array(&n_val, &n_array);
    CHECK2(err == NANOCBOR_OK, ERROR_PAYLOAD);

    uint8_t *tmp_buf = NULL;
    size_t tmp_len = 0;
    err = nanocbor_get_tstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
    CHECK2(err == NANOCBOR_OK, ERROR_PAYLOAD);
    const char *msg_sign_context = "Signature1";
    // msg_sign_context string size is 10
    CHECK2(tmp_len == 10, ERROR_PAYLOAD);
    CHECK2(memcmp(msg_sign_context, tmp_buf, tmp_len) == 0, ERROR_PAYLOAD);

    // null
    tmp_buf = NULL;
    tmp_len = 0;
    err = nanocbor_get_bstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
    CHECK2(err == NANOCBOR_OK, ERROR_PAYLOAD);

    // ext
    tmp_buf = NULL;
    tmp_len = 0;
    err = nanocbor_get_bstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
    CHECK2(err == NANOCBOR_OK, ERROR_PAYLOAD);

    // payload
    tmp_buf = NULL;
    tmp_len = 0;
    err = nanocbor_get_bstr(&n_array, (const uint8_t **)&tmp_buf, &tmp_len);
    CHECK2(err == NANOCBOR_OK, ERROR_PAYLOAD);
    CHECK2(tmp_len == CARDANO_LOCK_BLAKE2B_BLOCK_SIZE, ERROR_PAYLOAD);
    memcpy(payload, tmp_buf, tmp_len);

    nanocbor_leave_container(&n_val, &n_array);

exit:
    return err;
}
