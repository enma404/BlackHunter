/*
 * crypto_utils.c
 * BlackHunter Pro - Cryptographic Utilities
 * AES, XOR, Base64, and hashing utilities for encryption/obfuscation
 * Academic Penetration Testing Tool - Isolated Lab Only
 *
 * Compile: gcc -O2 -o crypto_utils crypto_utils.c
 * Usage:   ./crypto_utils <mode> <args>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>

/* ============================================= */
/* CONFIGURATION */
/* ============================================= */

#define MAX_INPUT 65536
#define MAX_OUTPUT 131072
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define AES_ROUNDS 14

/* ============================================= */
/* GLOBAL VARIABLES */
/* ============================================= */

static char g_output[MAX_OUTPUT];

/* ============================================= */
/* XOR ENCRYPTION */
/* ============================================= */

static int xor_crypt(const char *input, int input_len,
                     const char *key, int key_len,
                     char *output, int output_size) {
    if (key_len <= 0) return -1;
    if (input_len >= output_size) return -1;

    for (int i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }

    output[input_len] = '\0';
    return input_len;
}

static int xor_hex_encode(const char *input, const char *key,
                           char *output, int output_size) {
    int input_len = strlen(input);
    int key_len = strlen(key);
    int j = 0;

    if (key_len <= 0) return -1;

    for (int i = 0; i < input_len; i++) {
        unsigned char c = input[i] ^ key[i % key_len];

        if (j + 3 >= output_size) return -1;
        output[j++] = '\\';
        output[j++] = 'x';
        output[j++] = "0123456789abcdef"[(c >> 4) & 0x0F];
        output[j++] = "0123456789abcdef"[c & 0x0F];
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* ROT13 */
/* ============================================= */

static int rot13(const char *input, char *output, int output_size) {
    int i;

    for (i = 0; input[i] != '\0' && i < output_size - 1; i++) {
        char c = input[i];

        if (c >= 'a' && c <= 'z') {
            output[i] = ((c - 'a' + 13) % 26) + 'a';
        } else if (c >= 'A' && c <= 'Z') {
            output[i] = ((c - 'A' + 13) % 26) + 'A';
        } else {
            output[i] = c;
        }
    }

    output[i] = '\0';
    return i;
}

/* ============================================= */
/* BASE64 */
/* ============================================= */

static const char B64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const unsigned char *input, int input_len,
                         char *output, int output_size) {
    int i = 0, j = 0;
    unsigned char buf[3];
    unsigned char out[4];

    while (i < input_len) {
        int bytes = 0;

        for (int k = 0; k < 3; k++) {
            if (i < input_len) {
                buf[k] = input[i++];
                bytes++;
            } else {
                buf[k] = 0;
            }
        }

        out[0] = B64_TABLE[buf[0] >> 2];
        out[1] = B64_TABLE[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];
        out[2] = (bytes > 1) ? B64_TABLE[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)] : '=';
        out[3] = (bytes > 2) ? B64_TABLE[buf[2] & 0x3F] : '=';

        for (int k = 0; k < 4; k++) {
            if (j >= output_size - 1) return -1;
            output[j++] = out[k];
        }
    }

    output[j] = '\0';
    return j;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char *input, unsigned char *output, int output_size) {
    int len = strlen(input);
    int j = 0;
    int buf = 0;
    int bits = 0;

    for (int i = 0; i < len && j < output_size - 1; i++) {
        if (input[i] == '=') break;

        int val = b64_decode_char(input[i]);
        if (val < 0) continue;

        buf = (buf << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            output[j++] = (buf >> bits) & 0xFF;
        }
    }

    output[j] = '\0';
    return j;
}

/* ============================================= */
/* BASE64 URL-SAFE (for URLs and filenames) */
/* ============================================= */

static int base64url_encode(const unsigned char *input, int input_len,
                             char *output, int output_size) {
    int len = base64_encode(input, input_len, output, output_size);

    if (len < 0) return -1;

    for (int i = 0; i < len; i++) {
        if (output[i] == '+') output[i] = '-';
        else if (output[i] == '/') output[i] = '_';
    }

    /* Remove padding */
    while (len > 0 && output[len - 1] == '=') {
        output[--len] = '\0';
    }

    return len;
}

/* ============================================= */
/* SIMPLE AES (Educational - simplified) */
/* ============================================= */

/* AES S-Box */
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* AES Inverse S-Box */
static const uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* AES Round Constants */
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* Galois Multiplication */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;

    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;

        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;

        b >>= 1;
    }

    return p;
}

/* Key Expansion for AES-256 */
static void aes_key_expansion(const uint8_t *key, uint8_t *round_key) {
    int i, j;
    uint8_t temp[4];

    /* First round key = original key */
    for (i = 0; i < 32; i++) {
        round_key[i] = key[i];
    }

    /* Generate remaining round keys */
    int bytes_generated = 32;
    int rcon_iter = 1;

    while (bytes_generated < 240) {
        /* Copy previous word */
        for (i = 0; i < 4; i++) {
            temp[i] = round_key[bytes_generated - 4 + i];
        }

        /* Every 32 bytes (AES-256) */
        if (bytes_generated % 32 == 0) {
            /* Rotate */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            /* SubBytes */
            for (i = 0; i < 4; i++) {
                temp[i] = SBOX[temp[i]];
            }

            /* XOR with Rcon */
            temp[0] ^= RCON[rcon_iter++];
        } else if (bytes_generated % 32 == 16) {
            /* Extra SubBytes for AES-256 */
            for (i = 0; i < 4; i++) {
                temp[i] = SBOX[temp[i]];
            }
        }

        /* XOR with word 8 positions back */
        for (i = 0; i < 4; i++) {
            round_key[bytes_generated] = round_key[bytes_generated - 32] ^ temp[i];
            bytes_generated++;
        }
    }
}

/* Add Round Key */
static void add_round_key(uint8_t *state, const uint8_t *round_key, int round) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[round * 16 + i];
    }
}

/* SubBytes */
static void sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = SBOX[state[i]];
    }
}

/* InvSubBytes */
static void inv_sub_bytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = INV_SBOX[state[i]];
    }
}

/* ShiftRows */
static void shift_rows(uint8_t *state) {
    uint8_t temp;

    /* Row 1: shift left by 1 */
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    /* Row 2: shift left by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    /* Row 3: shift left by 3 (right by 1) */
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

/* InvShiftRows */
static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;

    /* Row 1: shift right by 1 */
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    /* Row 2: shift right by 2 */
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    /* Row 3: shift right by 3 */
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

/* MixColumns */
static void mix_columns(uint8_t *state) {
    uint8_t temp[4];

    for (int i = 0; i < 4; i++) {
        int col = i * 4;

        temp[0] = state[col];
        temp[1] = state[col + 1];
        temp[2] = state[col + 2];
        temp[3] = state[col + 3];

        state[col]     = gmul(temp[0], 2) ^ gmul(temp[1], 3) ^ temp[2] ^ temp[3];
        state[col + 1] = temp[0] ^ gmul(temp[1], 2) ^ gmul(temp[2], 3) ^ temp[3];
        state[col + 2] = temp[0] ^ temp[1] ^ gmul(temp[2], 2) ^ gmul(temp[3], 3);
        state[col + 3] = gmul(temp[0], 3) ^ temp[1] ^ temp[2] ^ gmul(temp[3], 2);
    }
}

/* InvMixColumns */
static void inv_mix_columns(uint8_t *state) {
    uint8_t temp[4];

    for (int i = 0; i < 4; i++) {
        int col = i * 4;

        temp[0] = state[col];
        temp[1] = state[col + 1];
        temp[2] = state[col + 2];
        temp[3] = state[col + 3];

        state[col]     = gmul(temp[0], 14) ^ gmul(temp[1], 11) ^ gmul(temp[2], 13) ^ gmul(temp[3], 9);
        state[col + 1] = gmul(temp[0], 9) ^ gmul(temp[1], 14) ^ gmul(temp[2], 11) ^ gmul(temp[3], 13);
        state[col + 2] = gmul(temp[0], 13) ^ gmul(temp[1], 9) ^ gmul(temp[2], 14) ^ gmul(temp[3], 11);
        state[col + 3] = gmul(temp[0], 11) ^ gmul(temp[1], 13) ^ gmul(temp[2], 9) ^ gmul(temp[3], 14);
    }
}

/* AES-256 Encrypt Block */
static void aes_encrypt_block(uint8_t *block, const uint8_t *round_key) {
    /* Initial round key */
    add_round_key(block, round_key, 0);

    /* 13 rounds */
    for (int round = 1; round < 14; round++) {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, round_key, round);
    }

    /* Final round (no mix_columns) */
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, round_key, 14);
}

/* AES-256 Decrypt Block */
static void aes_decrypt_block(uint8_t *block, const uint8_t *round_key) {
    /* Final round */
    add_round_key(block, round_key, 14);
    inv_shift_rows(block);
    inv_sub_bytes(block);

    /* 13 rounds */
    for (int round = 13; round > 0; round--) {
        add_round_key(block, round_key, round);
        inv_mix_columns(block);
        inv_shift_rows(block);
        inv_sub_bytes(block);
    }

    /* Initial round key */
    add_round_key(block, round_key, 0);
}

/* PKCS#7 Padding */
static int pkcs7_pad(uint8_t *data, int data_len, int block_size) {
    int pad_len = block_size - (data_len % block_size);

    for (int i = 0; i < pad_len; i++) {
        data[data_len + i] = (uint8_t)pad_len;
    }

    return data_len + pad_len;
}

static int pkcs7_unpad(uint8_t *data, int data_len) {
    if (data_len <= 0) return data_len;

    int pad_len = data[data_len - 1];

    if (pad_len <= 0 || pad_len > 16 || pad_len > data_len) {
        return data_len;
    }

    /* Verify padding */
    for (int i = data_len - pad_len; i < data_len; i++) {
        if (data[i] != pad_len) return data_len;
    }

    return data_len - pad_len;
}

/* AES-256 CBC Encrypt */
static int aes_cbc_encrypt(const uint8_t *plaintext, int plaintext_len,
                            const uint8_t *key, const uint8_t *iv,
                            uint8_t *ciphertext, int ciphertext_size) {
    uint8_t round_key[240];
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t prev[AES_BLOCK_SIZE];
    uint8_t padded[MAX_INPUT + AES_BLOCK_SIZE];
    int padded_len;

    /* Key expansion */
    aes_key_expansion(key, round_key);

    /* Copy and pad */
    if (plaintext_len + AES_BLOCK_SIZE > (int)sizeof(padded)) return -1;
    memcpy(padded, plaintext, plaintext_len);
    padded_len = pkcs7_pad(padded, plaintext_len, AES_BLOCK_SIZE);

    if (padded_len > ciphertext_size) return -1;

    /* Initialize prev with IV */
    memcpy(prev, iv, AES_BLOCK_SIZE);

    /* Encrypt each block */
    for (int i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        /* XOR with previous ciphertext (or IV) */
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = padded[i + j] ^ prev[j];
        }

        /* Encrypt block */
        aes_encrypt_block(block, round_key);

        /* Copy to output */
        memcpy(ciphertext + i, block, AES_BLOCK_SIZE);
        memcpy(prev, block, AES_BLOCK_SIZE);
    }

    return padded_len;
}

/* AES-256 CBC Decrypt */
static int aes_cbc_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                            const uint8_t *key, const uint8_t *iv,
                            uint8_t *plaintext, int plaintext_size) {
    uint8_t round_key[240];
    uint8_t block[AES_BLOCK_SIZE];
    uint8_t prev[AES_BLOCK_SIZE];
    int plaintext_len = 0;

    if (ciphertext_len % AES_BLOCK_SIZE != 0) return -1;

    /* Key expansion */
    aes_key_expansion(key, round_key);

    /* Initialize prev with IV */
    memcpy(prev, iv, AES_BLOCK_SIZE);

    /* Decrypt each block */
    for (int i = 0; i < ciphertext_len; i += AES_BLOCK_SIZE) {
        if (i + AES_BLOCK_SIZE > ciphertext_len) break;
        if (plaintext_len + AES_BLOCK_SIZE > plaintext_size) return -1;

        /* Copy ciphertext block */
        memcpy(block, ciphertext + i, AES_BLOCK_SIZE);

        /* Decrypt block */
        aes_decrypt_block(block, round_key);

        /* XOR with previous ciphertext (or IV) */
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            plaintext[plaintext_len + j] = block[j] ^ prev[j];
        }

        /* Save current ciphertext for next round */
        memcpy(prev, ciphertext + i, AES_BLOCK_SIZE);

        plaintext_len += AES_BLOCK_SIZE;
    }

    /* Remove padding */
    plaintext_len = pkcs7_unpad(plaintext, plaintext_len);

    plaintext[plaintext_len] = '\0';
    return plaintext_len;
}

/* ============================================= */
/* RANDOM KEY GENERATOR */
/* ============================================= */

static void generate_random_key(uint8_t *key, int len) {
    FILE *fp = fopen("/dev/urandom", "rb");

    if (fp != NULL) {
        size_t read_bytes = fread(key, 1, len, fp);
        fclose(fp);

        if (read_bytes == (size_t)len) return;
    }

    /* Fallback */
    srand(time(NULL) ^ getpid());
    for (int i = 0; i < len; i++) {
        key[i] = rand() & 0xFF;
    }
}

/* ============================================= */
/* HEX UTILITIES */
/* ============================================= */

static void hex_encode(const uint8_t *input, int len, char *output) {
    for (int i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", input[i]);
    }
    output[len * 2] = '\0';
}

static int hex_decode(const char *input, uint8_t *output, int output_size) {
    int len = strlen(input);
    int j = 0;

    for (int i = 0; i < len - 1 && j < output_size; i += 2) {
        char hi = input[i];
        char lo = input[i + 1];

        if (!isxdigit(hi) || !isxdigit(lo)) break;

        int h = (hi >= '0' && hi <= '9') ? hi - '0' :
                (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : hi - 'A' + 10;
        int l = (lo >= '0' && lo <= '9') ? lo - '0' :
                (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : lo - 'A' + 10;

        output[j++] = (h << 4) | l;
    }

    return j;
}

/* ============================================= */
/* KEY DERIVATION (Simple PBKDF) */
/* ============================================= */

static void derive_key(const char *password, uint8_t *key, int key_len) {
    /* Simple key derivation - use SHA-256 in production */
    int pwd_len = strlen(password);

    for (int i = 0; i < key_len; i++) {
        key[i] = password[i % pwd_len] ^ (uint8_t)((i * 7 + 13) & 0xFF);
    }
}

/* ============================================= */
/* PRINT BANNER */
/* ============================================= */

static void print_banner(void) {
    printf("\n");
    printf("\033[1;35m");
    printf("  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗     ██╗   ██╗████████╗██╗██╗     ███████╗\n");
    printf("  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗    ██║   ██║╚══██╔══╝██║██║     ██╔════╝\n");
    printf("  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║    ██║   ██║   ██║   ██║██║     ███████╗\n");
    printf("  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║    ██║   ██║   ██║   ██║██║     ╚════██║\n");
    printf("  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝    ╚██████╔╝   ██║   ██║███████╗███████║\n");
    printf("   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝      ╚═════╝    ╚═╝   ╚═╝╚══════╝╚══════╝\n");
    printf("\033[0m");
    printf("\033[1;36m");
    printf("                    Cryptographic Utilities v1.0\n");
    printf("                  Academic Penetration Testing Tool\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* PRINT USAGE */
/* ============================================= */

static void print_usage(const char *prog) {
    printf("BlackHunter Pro - Crypto Utils\n");
    printf("Usage: %s <mode> <args>\n\n", prog);
    printf("\033[1;36mModes:\033[0m\n");
    printf("  xor <text> <key>       - XOR encrypt text with key\n");
    printf("  rot13 <text>           - ROT13 encode\n");
    printf("  b64 <text>             - Base64 encode\n");
    printf("  b64d <text>            - Base64 decode\n");
    printf("  b64url <text>          - Base64 URL-safe encode\n");
    printf("  hex <text>             - Hex encode\n");
    printf("  hexd <hex>             - Hex decode\n");
    printf("  aes-enc <text> <pass>  - AES-256-CBC encrypt\n");
    printf("  aes-dec <hex> <pass>   - AES-256-CBC decrypt\n");
    printf("  genkey                 - Generate random 32-byte key\n");
    printf("  encode-all <text>      - Generate all encodings\n");
    printf("\n");
    printf("\033[1;36mExamples:\033[0m\n");
    printf("  %s xor 'secret' 'mykey'\n", prog);
    printf("  %s b64 'hello world'\n", prog);
    printf("  %s b64d 'aGVsbG8gd29ybGQ='\n", prog);
    printf("  %s aes-enc 'secret message' 'password123'\n", prog);
    printf("  %s encode-all 'payload'\n", prog);
    printf("\n");
}

/* ============================================= */
/* ENCODE ALL */
/* ============================================= */

static void encode_all(const char *input) {
    char output[MAX_OUTPUT];
    int len;

    printf("\n\033[1;33m═══════════════════════════════════════════════════════\033[0m\n");
    printf("\033[1;33m  All Encodings of: \"%s\"\033[0m\n", input);
    printf("\033[1;33m═══════════════════════════════════════════════════════\033[0m\n\n");

    /* Base64 */
    len = base64_encode((const unsigned char *)input, strlen(input), output, sizeof(output));
    if (len > 0) printf("\033[1;36m[*] Base64:\033[0m\n%s\n\n", output);

    /* Base64 URL */
    len = base64url_encode((const unsigned char *)input, strlen(input), output, sizeof(output));
    if (len > 0) printf("\033[1;36m[*] Base64 URL-safe:\033[0m\n%s\n\n", output);

    /* Hex */
    hex_encode((const uint8_t *)input, strlen(input), output);
    printf("\033[1;36m[*] Hex:\033[0m\n%s\n\n", output);

    /* ROT13 */
    len = rot13(input, output, sizeof(output));
    if (len > 0) printf("\033[1;36m[*] ROT13:\033[0m\n%s\n\n", output);

    /* XOR with key */
    const char *default_key = "BlackHunter";
    len = xor_hex_encode(input, default_key, output, sizeof(output));
    if (len > 0) printf("\033[1;36m[*] XOR (key='BlackHunter'):\033[0m\n%s\n\n", output);

    printf("\033[1;32m[+] All encodings generated\033[0m\n");
}

/* ============================================= */
/* MAIN */
/* ============================================= */

int main(int argc, char *argv[]) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];

    /* XOR */
    if (strcmp(mode, "xor") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s xor <text> <key>\033[0m\n", argv[0]);
            return 1;
        }

        char output[MAX_OUTPUT];
        int len = xor_crypt(argv[2], strlen(argv[2]), argv[3], strlen(argv[3]),
                            output, sizeof(output));

        if (len > 0) {
            printf("\033[1;36m[*] XOR Result (raw):\033[0m\n%s\n\n", output);

            char hex_out[MAX_OUTPUT];
            xor_hex_encode(argv[2], argv[3], hex_out, sizeof(hex_out));
            printf("\033[1;36m[*] XOR Result (hex):\033[0m\n%s\n", hex_out);
        }
    }
    /* ROT13 */
    else if (strcmp(mode, "rot13") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s rot13 <text>\033[0m\n", argv[0]);
            return 1;
        }

        char output[MAX_OUTPUT];
        rot13(argv[2], output, sizeof(output));
        printf("\033[1;36m[*] ROT13:\033[0m\n%s\n", output);
    }
    /* BASE64 ENCODE */
    else if (strcmp(mode, "b64") == 0 || strcmp(mode, "base64") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s b64 <text>\033[0m\n", argv[0]);
            return 1;
        }

        char output[MAX_OUTPUT];
        base64_encode((const unsigned char *)argv[2], strlen(argv[2]), output, sizeof(output));
        printf("\033[1;36m[*] Base64:\033[0m\n%s\n", output);
    }
    /* BASE64 DECODE */
    else if (strcmp(mode, "b64d") == 0 || strcmp(mode, "b64decode") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s b64d <base64>\033[0m\n", argv[0]);
            return 1;
        }

        unsigned char output[MAX_OUTPUT];
        int len = base64_decode(argv[2], output, sizeof(output));

        if (len > 0) {
            output[len] = '\0';
            printf("\033[1;36m[*] Decoded:\033[0m\n%s\n", output);
        } else {
            fprintf(stderr, "\033[1;31m[!] Decode failed\033[0m\n");
        }
    }
    /* BASE64 URL */
    else if (strcmp(mode, "b64url") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s b64url <text>\033[0m\n", argv[0]);
            return 1;
        }

        char output[MAX_OUTPUT];
        base64url_encode((const unsigned char *)argv[2], strlen(argv[2]), output, sizeof(output));
        printf("\033[1;36m[*] Base64 URL-safe:\033[0m\n%s\n", output);
    }
    /* HEX ENCODE */
    else if (strcmp(mode, "hex") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s hex <text>\033[0m\n", argv[0]);
            return 1;
        }

        char output[MAX_OUTPUT];
        hex_encode((const uint8_t *)argv[2], strlen(argv[2]), output);
        printf("\033[1;36m[*] Hex:\033[0m\n%s\n", output);
    }
    /* HEX DECODE */
    else if (strcmp(mode, "hexd") == 0 || strcmp(mode, "unhex") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s hexd <hex>\033[0m\n", argv[0]);
            return 1;
        }

        uint8_t output[MAX_OUTPUT];
        int len = hex_decode(argv[2], output, sizeof(output));

        if (len > 0) {
            printf("\033[1;36m[*] Decoded (%d bytes):\033[0m\n", len);
            fwrite(output, 1, len, stdout);
            printf("\n");
        } else {
            fprintf(stderr, "\033[1;31m[!] Decode failed\033[0m\n");
        }
    }
    /* AES ENCRYPT */
    else if (strcmp(mode, "aes-enc") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s aes-enc <text> <password>\033[0m\n", argv[0]);
            return 1;
        }

        uint8_t key[AES_KEY_SIZE];
        uint8_t iv[AES_BLOCK_SIZE];
        uint8_t ciphertext[MAX_INPUT + AES_BLOCK_SIZE];

        /* Derive key from password */
        derive_key(argv[3], key, AES_KEY_SIZE);

        /* Generate random IV */
        generate_random_key(iv, AES_BLOCK_SIZE);

        /* Encrypt */
        int cipher_len = aes_cbc_encrypt((const uint8_t *)argv[2], strlen(argv[2]),
                                          key, iv, ciphertext, sizeof(ciphertext));

        if (cipher_len > 0) {
            char iv_hex[AES_BLOCK_SIZE * 2 + 1];
            char cipher_hex[MAX_INPUT * 2 + 1];

            hex_encode(iv, AES_BLOCK_SIZE, iv_hex);
            hex_encode(ciphertext, cipher_len, cipher_hex);

            printf("\033[1;36m[*] IV (hex):\033[0m\n%s\n", iv_hex);
            printf("\033[1;36m[*] Ciphertext (hex):\033[0m\n%s\n", cipher_hex);
            printf("\033[1;32m[+] Combined (IV+Cipher):\033[0m\n%s%s\n", iv_hex, cipher_hex);
        } else {
            fprintf(stderr, "\033[1;31m[!] Encryption failed\033[0m\n");
        }
    }
    /* AES DECRYPT */
    else if (strcmp(mode, "aes-dec") == 0) {
        if (argc < 4) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s aes-dec <hex> <password>\033[0m\n", argv[0]);
            return 1;
        }

        uint8_t key[AES_KEY_SIZE];
        uint8_t iv[AES_BLOCK_SIZE];
        uint8_t ciphertext[MAX_INPUT];
        uint8_t plaintext[MAX_INPUT];

        /* Derive key */
        derive_key(argv[3], key, AES_KEY_SIZE);

        /* Decode hex */
        int hex_len = strlen(argv[2]);
        if (hex_len < AES_BLOCK_SIZE * 2) {
            fprintf(stderr, "\033[1;31m[!] Invalid input\033[0m\n");
            return 1;
        }

        /* Extract IV (first 32 hex chars) */
        char iv_hex[AES_BLOCK_SIZE * 2 + 1];
        strncpy(iv_hex, argv[2], AES_BLOCK_SIZE * 2);
        iv_hex[AES_BLOCK_SIZE * 2] = '\0';
        hex_decode(iv_hex, iv, AES_BLOCK_SIZE);

        /* Extract ciphertext */
        int cipher_hex_len = hex_len - AES_BLOCK_SIZE * 2;
        int cipher_len = hex_decode(argv[2] + AES_BLOCK_SIZE * 2, ciphertext, sizeof(ciphertext));

        if (cipher_len <= 0) {
            fprintf(stderr, "\033[1;31m[!] Invalid ciphertext\033[0m\n");
            return 1;
        }

        /* Decrypt */
        int plain_len = aes_cbc_decrypt(ciphertext, cipher_len, key, iv,
                                         plaintext, sizeof(plaintext));

        if (plain_len > 0) {
            plaintext[plain_len] = '\0';
            printf("\033[1;36m[*] Decrypted:\033[0m\n%s\n", plaintext);
        } else {
            fprintf(stderr, "\033[1;31m[!] Decryption failed\033[0m\n");
        }
    }
    /* GENERATE KEY */
    else if (strcmp(mode, "genkey") == 0) {
        uint8_t key[32];
        char hex_key[65];

        generate_random_key(key, 32);
        hex_encode(key, 32, hex_key);

        printf("\033[1;36m[*] Random 32-byte key:\033[0m\n%s\n", hex_key);
    }
    /* ENCODE ALL */
    else if (strcmp(mode, "encode-all") == 0 || strcmp(mode, "all") == 0) {
        if (argc < 3) {
            fprintf(stderr, "\033[1;31m[!] Usage: %s encode-all <text>\033[0m\n", argv[0]);
            return 1;
        }
        encode_all(argv[2]);
    }
    /* HELP */
    else if (strcmp(mode, "help") == 0 || strcmp(mode, "-h") == 0) {
        print_usage(argv[0]);
    }
    /* UNKNOWN */
    else {
        fprintf(stderr, "\033[1;31m[!] Unknown mode: %s\033[0m\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    printf("\n\033[1;32m[+] Done!\033[0m\n\n");
    return 0;
}

/* ============================================= */
/* COMPILE INSTRUCTIONS */
/* ============================================= */

/*
 * Compile:
 *   gcc -O2 -o crypto_utils crypto_utils.c
 *   clang -O2 -o crypto_utils crypto_utils.c
 *
 * Usage:
 *   ./crypto_utils xor "secret" "mykey"
 *   ./crypto_utils rot13 "hello"
 *   ./crypto_utils b64 "hello world"
 *   ./crypto_utils b64d "aGVsbG8gd29ybGQ="
 *   ./crypto_utils b64url "hello"
 *   ./crypto_utils hex "hello"
 *   ./crypto_utils hexd "68656c6c6f"
 *   ./crypto_utils aes-enc "secret message" "password123"
 *   ./crypto_utils aes-dec "<hex output>" "password123"
 *   ./crypto_utils genkey
 *   ./crypto_utils encode-all "payload"
 */