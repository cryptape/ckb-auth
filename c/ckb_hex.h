#ifndef _CBK_C_STDLIB_CKB_HEX_H_
#define _CBK_C_STDLIB_CKB_HEX_H_
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum CkbHexErrorCodeType {
    ERROR_HEX_OUT_OF_BOUNDS = 30,
    ERROR_HEX_INVALID_HEX,
};

static int _ckb_getbin(uint8_t x, uint8_t* out) {
    if (x >= '0' && x <= '9') {
        *out = x - '0';
    } else if (x >= 'A' && x <= 'F') {
        *out = x - 'A' + 10;
    } else if (x >= 'a' && x <= 'f') {
        *out = x - 'a' + 10;
    } else {
        return ERROR_HEX_INVALID_HEX;
    }
    return 0;
}

static void _ckb_gethex(uint8_t x, char* out) {
    static char s_mapping[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    out[0] = s_mapping[(x >> 4) & 0x0F];
    out[1] = s_mapping[x & 0x0F];
}

int _ckb_safe_strlen(const char* s, uint32_t limit, uint32_t* length) {
    if (s == NULL) return ERROR_HEX_OUT_OF_BOUNDS;

    uint32_t count = 0;
    for (; *s; s++) {
        count++;
        if (count > limit) return ERROR_HEX_OUT_OF_BOUNDS;
    }
    *length = count;
    return 0;
}

// the string length of "hex" should be no more than bin_len*2
// "length" returns the bytes count written in "bin"
static int ckb_hex2bin(const char* hex, uint8_t* bin, uint32_t bin_len,
                       uint32_t* length) {
    uint32_t limit = 2 * bin_len;
    uint32_t hex_len;
    int err = _ckb_safe_strlen(hex, limit, &hex_len);
    if (err != 0) return err;
    if (hex_len % 2 != 0) return ERROR_HEX_INVALID_HEX;
    *length = hex_len / 2;
    if (*length > bin_len) {
        return ERROR_HEX_OUT_OF_BOUNDS;
    }
    for (uint32_t i = 0; i < *length; i++) {
        uint8_t high, low;
        err = _ckb_getbin(hex[i * 2], &high);
        if (err != 0) return err;
        err = _ckb_getbin(hex[i * 2 + 1], &low);
        if (err != 0) return err;
        bin[i] = high << 4 | low;
    }
    return 0;
}

static int ckb_bin2hex(const uint8_t* bin, uint32_t bin_len, char* hex,
                       uint32_t hex_len, uint32_t* length, bool last_field) {
    if (hex_len < (bin_len * 2 + 1)) {
        return ERROR_HEX_OUT_OF_BOUNDS;
    }
    for (uint32_t i = 0; i < bin_len; i++) {
        _ckb_gethex(bin[i], hex + 2 * i);
    }
    if (last_field)
        *(hex + bin_len * 2) = 0;
    else
        *(hex + bin_len * 2) = ':';

    *length = 2 * bin_len + 1;
    return 0;
}

#endif  // _CBK_C_STDLIB_CKB_HEX_H_
