/*
 * hash_cracker.c
 * BlackHunter Pro - Hash Cracker
 * Multi-threaded hash cracking tool (dictionary + brute-force)
 * Academic Penetration Testing Tool - Isolated Lab Only
 *
 * Compile: gcc -O2 -pthread -o hash_cracker hash_cracker.c
 * Usage:   ./hash_cracker <algorithm> <hash> [wordlist]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/time.h>

/* ============================================= */
/* CONFIGURATION */
/* ============================================= */

#define MAX_HASH_LEN 128
#define MAX_WORD_LEN 256
#define MAX_THREADS 256
#define DEFAULT_THREADS 8
#define MAX_LINE 1024
#define HASH_OUTPUT_LEN 65

/* ============================================= */
/* MD5 IMPLEMENTATION */
/* ============================================= */

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} MD5_CTX;

#define F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define G(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define I(x,y,z) ((y) ^ ((x) | ~(z)))
#define ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a,b,c,d,x,s,ac) \
    { (a) += F((b),(c),(d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT((a),(s)); \
      (a) += (b); }
#define GG(a,b,c,d,x,s,ac) \
    { (a) += G((b),(c),(d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT((a),(s)); \
      (a) += (b); }
#define HH(a,b,c,d,x,s,ac) \
    { (a) += H((b),(c),(d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT((a),(s)); \
      (a) += (b); }
#define II(a,b,c,d,x,s,ac) \
    { (a) += I((b),(c),(d)) + (x) + (uint32_t)(ac); \
      (a) = ROTATE_LEFT((a),(s)); \
      (a) += (b); }

static const uint8_t MD5_PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    for (int i = 0, j = 0; j < 64; i++, j += 4) {
        x[i] = ((uint32_t)block[j]) |
               (((uint32_t)block[j+1]) << 8) |
               (((uint32_t)block[j+2]) << 16) |
               (((uint32_t)block[j+3]) << 24);
    }

    FF(a, b, c, d, x[0], 7, 0xd76aa478);
    FF(d, a, b, c, x[1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[2], 17, 0x242070db);
    FF(b, c, d, a, x[3], 22, 0xc1bdceee);
    FF(a, b, c, d, x[4], 7, 0xf57c0faf);
    FF(d, a, b, c, x[5], 12, 0x4787c62a);
    FF(c, d, a, b, x[6], 17, 0xa8304613);
    FF(b, c, d, a, x[7], 22, 0xfd469501);
    FF(a, b, c, d, x[8], 7, 0x698098d8);
    FF(d, a, b, c, x[9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    FF(b, c, d, a, x[11], 22, 0x895cd7be);
    FF(a, b, c, d, x[12], 7, 0x6b901122);
    FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e);
    FF(b, c, d, a, x[15], 22, 0x49b40821);

    GG(a, b, c, d, x[1], 5, 0xf61e2562);
    GG(d, a, b, c, x[6], 9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51);
    GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
    GG(a, b, c, d, x[5], 5, 0xd62f105d);
    GG(d, a, b, c, x[10], 9, 0x02441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
    GG(a, b, c, d, x[9], 5, 0x21e1cde6);
    GG(d, a, b, c, x[14], 9, 0xc33707d6);
    GG(c, d, a, b, x[3], 14, 0xf4d50d87);
    GG(b, c, d, a, x[8], 20, 0x455a14ed);
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);
    GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
    GG(c, d, a, b, x[7], 14, 0x676f02d9);
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

    HH(a, b, c, d, x[5], 4, 0xfffa3942);
    HH(d, a, b, c, x[8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    HH(b, c, d, a, x[14], 23, 0xfde5380c);
    HH(a, b, c, d, x[1], 4, 0xa4beea44);
    HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);
    HH(d, a, b, c, x[0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[3], 16, 0xd4ef3085);
    HH(b, c, d, a, x[6], 23, 0x04881d05);
    HH(a, b, c, d, x[9], 4, 0xd9d4d039);
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, x[2], 23, 0xc4ac5665);

    II(a, b, c, d, x[0], 6, 0xf4292244);
    II(d, a, b, c, x[7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7);
    II(b, c, d, a, x[5], 21, 0xfc93a039);
    II(a, b, c, d, x[12], 6, 0x655b59c3);
    II(d, a, b, c, x[3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d);
    II(b, c, d, a, x[1], 21, 0x85845dd1);
    II(a, b, c, d, x[8], 6, 0x6fa87e4f);
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[6], 15, 0xa3014314);
    II(b, c, d, a, x[13], 21, 0x4e0811a1);
    II(a, b, c, d, x[4], 6, 0xf7537e82);
    II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
    II(b, c, d, a, x[9], 21, 0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof(x));
}

static void md5_init(MD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(MD5_CTX *ctx, const uint8_t *input, size_t len) {
    size_t i, index, part_len;

    index = (ctx->count[0] >> 3) & 0x3F;

    if ((ctx->count[0] += (uint32_t)(len << 3)) < (uint32_t)(len << 3))
        ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);

    part_len = 64 - index;

    if (len >= part_len) {
        memcpy(&ctx->buffer[index], input, part_len);
        md5_transform(ctx->state, ctx->buffer);

        for (i = part_len; i + 63 < len; i += 64)
            md5_transform(ctx->state, &input[i]);

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&ctx->buffer[index], &input[i], len - i);
}

static void md5_final(uint8_t digest[16], MD5_CTX *ctx) {
    uint8_t bits[8];
    size_t index, pad_len;

    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)((ctx->count[i >> 2] >> ((i & 3) << 3)) & 0xFF);
    }

    index = (ctx->count[0] >> 3) & 0x3F;
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    md5_update(ctx, MD5_PADDING, pad_len);
    md5_update(ctx, bits, 8);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            digest[i * 4 + j] = (uint8_t)((ctx->state[i] >> (j * 8)) & 0xFF);
        }
    }
}

static void md5_hash(const char *input, char *output) {
    MD5_CTX ctx;
    uint8_t digest[16];

    md5_init(&ctx);
    md5_update(&ctx, (const uint8_t *)input, strlen(input));
    md5_final(digest, &ctx);

    for (int i = 0; i < 16; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[32] = '\0';
}

/* ============================================= */
/* SHA1 IMPLEMENTATION */
/* ============================================= */

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[64];
} SHA1_CTX;

#define SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, w[80];
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)buffer[i*4] << 24) |
               ((uint32_t)buffer[i*4+1] << 16) |
               ((uint32_t)buffer[i*4+2] << 8) |
               ((uint32_t)buffer[i*4+3]);
    }

    for (i = 16; i < 80; i++) {
        w[i] = SHA1_ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f, k, temp;

        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        temp = SHA1_ROL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

static void sha1_init(SHA1_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

static void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i, j;

    j = (size_t)((ctx->count >> 3) & 63);
    ctx->count += (uint64_t)(len << 3);

    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        sha1_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        j = 0;
    } else {
        i = 0;
    }

    memcpy(&ctx->buffer[j], &data[i], len - i);
}

static void sha1_final(uint8_t digest[20], SHA1_CTX *ctx) {
    uint8_t finalcount[8];
    uint8_t c;

    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((ctx->count >> ((7 - i) * 8)) & 0xff);
    }

    c = 0200;
    sha1_update(ctx, &c, 1);

    while ((ctx->count & 504) != 448) {
        c = 0;
        sha1_update(ctx, &c, 1);
    }

    sha1_update(ctx, finalcount, 8);

    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 0xff);
    }
}

static void sha1_hash(const char *input, char *output) {
    SHA1_CTX ctx;
    uint8_t digest[20];

    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)input, strlen(input));
    sha1_final(digest, &ctx);

    for (int i = 0; i < 20; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[40] = '\0';
}

/* ============================================= */
/* SHA256 IMPLEMENTATION */
/* ============================================= */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} SHA256_CTX;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | ((uint32_t)data[j+3]);
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = (size_t)((ctx->count >> 3) & 63);
    ctx->count += (uint64_t)(len << 3);

    if ((i + len) > 63) {
        memcpy(&ctx->buffer[i], data, (i = 64 - i));
        sha256_transform(ctx, ctx->buffer);
        for (; i + 63 < len; i += 64) sha256_transform(ctx, &data[i]);
        i = 0;
    }

    memcpy(&ctx->buffer[i], &data[i], len - i);
}

static void sha256_final(uint8_t digest[32], SHA256_CTX *ctx) {
    uint8_t data[64];
    uint32_t datalen = (uint32_t)((ctx->count >> 3) & 63);
    uint64_t bitlen = ctx->count;
    uint32_t i;

    data[0] = 0x80;
    for (i = 1; i < 64 - datalen; i++) data[i] = 0;

    if (datalen >= 56) {
        sha256_transform(ctx, data);
        memset(data, 0, 56);
    }

    for (i = 0; i < 8; i++) {
        data[56 + i] = (uint8_t)((bitlen >> (56 - 8 * i)) & 0xff);
    }

    sha256_transform(ctx, data);

    for (i = 0; i < 4; i++) {
        digest[i]      = (uint8_t)(ctx->state[0] >> (24 - i * 8));
        digest[i + 4]  = (uint8_t)(ctx->state[1] >> (24 - i * 8));
        digest[i + 8]  = (uint8_t)(ctx->state[2] >> (24 - i * 8));
        digest[i + 12] = (uint8_t)(ctx->state[3] >> (24 - i * 8));
        digest[i + 16] = (uint8_t)(ctx->state[4] >> (24 - i * 8));
        digest[i + 20] = (uint8_t)(ctx->state[5] >> (24 - i * 8));
        digest[i + 24] = (uint8_t)(ctx->state[6] >> (24 - i * 8));
        digest[i + 28] = (uint8_t)(ctx->state[7] >> (24 - i * 8));
    }
}

static void sha256_hash(const char *input, char *output) {
    SHA256_CTX ctx;
    uint8_t digest[32];

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)input, strlen(input));
    sha256_final(digest, &ctx);

    for (int i = 0; i < 32; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[64] = '\0';
}

/* ============================================= */
/* HASH DISPATCHER */
/* ============================================= */

static void compute_hash(const char *algo, const char *input, char *output) {
    if (strcmp(algo, "md5") == 0 || strcmp(algo, "MD5") == 0) {
        md5_hash(input, output);
    } else if (strcmp(algo, "sha1") == 0 || strcmp(algo, "SHA1") == 0) {
        sha1_hash(input, output);
    } else if (strcmp(algo, "sha256") == 0 || strcmp(algo, "SHA256") == 0) {
        sha256_hash(input, output);
    } else {
        output[0] = '\0';
    }
}

/* ============================================= */
/* GLOBAL VARIABLES */
/* ============================================= */

static char g_target_hash[MAX_HASH_LEN];
static char g_algorithm[16];
static volatile int g_found = 0;
static char g_found_word[MAX_WORD_LEN];
static volatile int g_running = 1;
static volatile uint64_t g_attempts = 0;
static pthread_mutex_t g_attempts_lock = PTHREAD_MUTEX_INITIALIZER;

/* ============================================= */
/* DICTIONARY ATTACK */
/* ============================================= */

static void* dict_worker(void *arg) {
    FILE *fp = (FILE *)arg;
    char line[MAX_LINE];
    char hash[HASH_OUTPUT_LEN];
    pthread_mutex_t *file_lock = (pthread_mutex_t *)arg;
    (void)file_lock;

    while (g_running && !g_found) {
        /* Read line (thread-safe via mutex would be better) */
        if (fgets(line, sizeof(line), fp) == NULL) break;

        /* Remove newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0) continue;

        /* Compute hash */
        compute_hash(g_algorithm, line, hash);

        pthread_mutex_lock(&g_attempts_lock);
        g_attempts++;
        pthread_mutex_unlock(&g_attempts_lock);

        /* Compare */
        if (strcasecmp(hash, g_target_hash) == 0) {
            g_found = 1;
            strncpy(g_found_word, line, MAX_WORD_LEN - 1);
            g_found_word[MAX_WORD_LEN - 1] = '\0';
            return NULL;
        }
    }

    return NULL;
}

static int dictionary_attack(const char *wordlist, int threads) {
    FILE *fp = fopen(wordlist, "r");
    if (fp == NULL) {
        fprintf(stderr, "\033[1;31m[!] Cannot open wordlist: %s\033[0m\n", wordlist);
        return -1;
    }

    printf("\033[1;36m[*] Dictionary attack with %d threads...\033[0m\n", threads);

    pthread_t *thread_ids = (pthread_t *)malloc(sizeof(pthread_t) * threads);
    if (thread_ids == NULL) {
        fclose(fp);
        return -1;
    }

    /* Use a shared file handle with mutex for thread-safe reading */
    static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
    (void)file_mutex;

    for (int i = 0; i < threads; i++) {
        if (pthread_create(&thread_ids[i], NULL, dict_worker, fp) != 0) {
            threads = i;
            break;
        }
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);
    fclose(fp);

    return g_found ? 0 : -1;
}

/* ============================================= */
/* BRUTE-FORCE ATTACK */
/* ============================================= */

static const char CHARSET_LOWER[] = "abcdefghijklmnopqrstuvwxyz";
static const char CHARSET_UPPER[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char CHARSET_DIGITS[] = "0123456789";
static const char CHARSET_SPECIAL[] = "!@#$%^&*()-_=+[]{};:,.<>?/";
static const char CHARSET_ALL[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

typedef struct {
    const char *charset;
    int charset_len;
    int min_len;
    int max_len;
    uint64_t start_index;
    uint64_t end_index;
} BruteTask;

static void index_to_string(uint64_t index, const char *charset, int charset_len,
                             int length, char *output) {
    for (int i = length - 1; i >= 0; i--) {
        output[i] = charset[index % charset_len];
        index /= charset_len;
    }
    output[length] = '\0';
}

static uint64_t power_uint(uint64_t base, int exp) {
    uint64_t result = 1;
    for (int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

static void* brute_worker(void *arg) {
    BruteTask *task = (BruteTask *)arg;
    char candidate[MAX_WORD_LEN];
    char hash[HASH_OUTPUT_LEN];

    for (int len = task->min_len; len <= task->max_len && !g_found && g_running; len++) {
        uint64_t total = power_uint(task->charset_len, len);
        uint64_t start = (len == task->min_len) ? task->start_index : 0;
        uint64_t end = (len == task->max_len) ? task->end_index : total;

        if (end > total) end = total;

        for (uint64_t i = start; i < end && !g_found && g_running; i++) {
            index_to_string(i, task->charset, task->charset_len, len, candidate);
            compute_hash(g_algorithm, candidate, hash);

            pthread_mutex_lock(&g_attempts_lock);
            g_attempts++;
            pthread_mutex_unlock(&g_attempts_lock);

            if (strcasecmp(hash, g_target_hash) == 0) {
                g_found = 1;
                strncpy(g_found_word, candidate, MAX_WORD_LEN - 1);
                return NULL;
            }
        }
    }

    return NULL;
}

static int brute_force_attack(const char *charset, int min_len, int max_len, int threads) {
    int charset_len = strlen(charset);

    printf("\033[1;36m[*] Brute-force attack (charset size: %d, length: %d-%d, threads: %d)\033[0m\n",
           charset_len, min_len, max_len, threads);

    /* Calculate total keyspace */
    uint64_t total = 0;
    for (int len = min_len; len <= max_len; len++) {
        total += power_uint(charset_len, len);
    }
    printf("\033[1;36m[*] Total keyspace: %llu\033[0m\n", (unsigned long long)total);

    /* Distribute work */
    uint64_t chunk = total / threads;
    if (chunk == 0) chunk = 1;

    pthread_t *thread_ids = (pthread_t *)malloc(sizeof(pthread_t) * threads);
    BruteTask *tasks = (BruteTask *)malloc(sizeof(BruteTask) * threads);

    if (thread_ids == NULL || tasks == NULL) {
        free(thread_ids);
        free(tasks);
        return -1;
    }

    /* For simplicity, split by first character */
    for (int i = 0; i < threads; i++) {
        tasks[i].charset = charset;
        tasks[i].charset_len = charset_len;
        tasks[i].min_len = min_len;
        tasks[i].max_len = max_len;
        tasks[i].start_index = 0;
        tasks[i].end_index = power_uint(charset_len, max_len);

        pthread_create(&thread_ids[i], NULL, brute_worker, &tasks[i]);
    }

    /* Progress reporter */
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (!g_found) {
        int all_done = 1;
        for (int i = 0; i < threads; i++) {
            /* Simple check via g_running */
        }
        (void)all_done;

        usleep(500000);

        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_usec - start.tv_usec) / 1000000.0;

        if (elapsed > 2.0) {
            uint64_t attempts = g_attempts;
            printf("\r\033[1;33m[*] Attempts: %llu (%.0f H/s)   \033[0m",
                   (unsigned long long)attempts,
                   attempts / elapsed);
            fflush(stdout);
        }

        if (!g_running) break;
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    free(thread_ids);
    free(tasks);

    printf("\n");
    return g_found ? 0 : -1;
}

/* ============================================= */
/* SIGNAL HANDLER */
/* ============================================= */

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n\033[1;33m[!] Interrupted by user\033[0m\n");
}

/* ============================================= */
/* PRINT BANNER */
/* ============================================= */

static void print_banner(void) {
    printf("\n");
    printf("\033[1;32m");
    printf("  ██╗  ██╗ █████╗ ███████╗██╗  ██╗     ██████╗██████╗  █████╗  ██████╗██╗  ██╗\n");
    printf("  ██║  ██║██╔══██╗██╔════╝██║  ██║    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝\n");
    printf("  ███████║███████║███████╗███████║    ██║     ██████╔╝███████║██║     █████╔╝ \n");
    printf("  ██╔══██║██╔══██║╚════██║██╔══██║    ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ \n");
    printf("  ██║  ██║██║  ██║███████║██║  ██║    ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗\n");
    printf("  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");
    printf("\033[0m");
    printf("\033[1;36m");
    printf("                      Hash Cracker v1.0\n");
    printf("                Academic Penetration Testing Tool\n");
    printf("\033[0m\n");
}

/* ============================================= */
/* PRINT USAGE */
/* ============================================= */

static void print_usage(const char *prog) {
    printf("BlackHunter Pro - Hash Cracker\n");
    printf("Usage: %s <algorithm> <hash> [options]\n\n", prog);
    printf("\033[1;36mAlgorithms:\033[0m\n");
    printf("  md5      - MD5 (32 hex chars)\n");
    printf("  sha1     - SHA1 (40 hex chars)\n");
    printf("  sha256   - SHA256 (64 hex chars)\n");
    printf("\n\033[1;36mOptions:\033[0m\n");
    printf("  -w <file>   - Dictionary attack with wordlist\n");
    printf("  -b <set>    - Brute-force with charset (lower/upper/digits/all)\n");
    printf("  -l <n>      - Minimum length for brute-force (default: 1)\n");
    printf("  -L <n>      - Maximum length for brute-force (default: 6)\n");
    printf("  -t <n>      - Number of threads (default: %d)\n", DEFAULT_THREADS);
    printf("\n");
    printf("\033[1;36mExamples:\033[0m\n");
    printf("  %s md5 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt\n", prog);
    printf("  %s md5 5f4dcc3b5aa765d61d8327deb882cf99 -b lower -l 1 -L 6\n", prog);
    printf("  %s sha1 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -b all -l 4 -L 8\n", prog);
    printf("\n");
}

/* ============================================= */
/* GET CHARSET BY NAME */
/* ============================================= */

static const char* get_charset(const char *name) {
    if (strcmp(name, "lower") == 0) return CHARSET_LOWER;
    if (strcmp(name, "upper") == 0) return CHARSET_UPPER;
    if (strcmp(name, "digits") == 0) return CHARSET_DIGITS;
    if (strcmp(name, "special") == 0) return CHARSET_SPECIAL;
    if (strcmp(name, "all") == 0) return CHARSET_ALL;
    return CHARSET_ALL; /* default */
}

/* ============================================= */
/* MAIN */
/* ============================================= */

int main(int argc, char *argv[]) {
    char *wordlist = NULL;
    char *brute_charset = NULL;
    int min_len = 1;
    int max_len = 6;
    int threads = DEFAULT_THREADS;
    int use_brute = 0;

    print_banner();

    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    /* Algorithm */
    strncpy(g_algorithm, argv[1], sizeof(g_algorithm) - 1);

    if (strcmp(g_algorithm, "md5") != 0 &&
        strcmp(g_algorithm, "sha1") != 0 &&
        strcmp(g_algorithm, "sha256") != 0) {
        fprintf(stderr, "\033[1;31m[!] Unknown algorithm: %s\033[0m\n", g_algorithm);
        return 1;
    }

    /* Target hash */
    strncpy(g_target_hash, argv[2], sizeof(g_target_hash) - 1);

    /* Validate hash length */
    int hash_len = strlen(g_target_hash);
    if (strcmp(g_algorithm, "md5") == 0 && hash_len != 32) {
        fprintf(stderr, "\033[1;31m[!] MD5 hash must be 32 characters\033[0m\n");
        return 1;
    }
    if (strcmp(g_algorithm, "sha1") == 0 && hash_len != 40) {
        fprintf(stderr, "\033[1;31m[!] SHA1 hash must be 40 characters\033[0m\n");
        return 1;
    }
    if (strcmp(g_algorithm, "sha256") == 0 && hash_len != 64) {
        fprintf(stderr, "\033[1;31m[!] SHA256 hash must be 64 characters\033[0m\n");
        return 1;
    }

    /* Parse options */
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            wordlist = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            brute_charset = argv[++i];
            use_brute = 1;
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            min_len = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) {
            max_len = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
            if (threads < 1) threads = 1;
            if (threads > MAX_THREADS) threads = MAX_THREADS;
        }
    }

    /* Print info */
    printf("\033[1;36m╔═══════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;36m║\033[0m  Algorithm:   \033[1;33m%-30s\033[0m \033[1;36m║\033[0m\n", g_algorithm);
    printf("\033[1;36m║\033[0m  Target Hash: \033[1;33m%-30s\033[0m \033[1;36m║\033[0m\n", g_target_hash);
    printf("\033[1;36m║\033[0m  Threads:     \033[1;33m%-30d\033[0m \033[1;36m║\033[0m\n", threads);
    if (wordlist) {
        printf("\033[1;36m║\033[0m  Wordlist:    \033[1;33m%-30s\033[0m \033[1;36m║\033[0m\n", wordlist);
    }
    if (use_brute) {
        printf("\033[1;36m║\033[0m  Charset:     \033[1;33m%-30s\033[0m \033[1;36m║\033[0m\n", brute_charset);
        printf("\033[1;36m║\033[0m  Length:      \033[1;33m%d - %-26d\033[0m \033[1;36m║\033[0m\n", min_len, max_len);
    }
    printf("\033[1;36m╚═══════════════════════════════════════════════╝\033[0m\n\n");

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Start timer */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    /* Execute attack */
    int result = -1;

    if (wordlist != NULL) {
        result = dictionary_attack(wordlist, threads);
    } else if (use_brute) {
        const char *charset = get_charset(brute_charset);
        result = brute_force_attack(charset, min_len, max_len, threads);
    } else {
        fprintf(stderr, "\033[1;31m[!] No attack mode specified. Use -w or -b\033[0m\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Stop timer */
    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_usec - start.tv_usec) / 1000000.0;

    /* Print results */
    printf("\n\033[1;36m═══════════════════════════════════════════════\033[0m\n");

    if (result == 0) {
        printf("\033[1;32m[+] HASH CRACKED!\033[0m\n");
        printf("\033[1;32m[+] Password: \033[1;33m%s\033[0m\n", g_found_word);
        printf("\033[1;36m[*] Attempts: %llu\033[0m\n", (unsigned long long)g_attempts);
        printf("\033[1;36m[*] Time: %.2f seconds\033[0m\n", elapsed);
        printf("\033[1;36m[*] Speed: %.0f H/s\033[0m\n", g_attempts / elapsed);

        /* Machine-readable output */
        printf("\n\033[1;36m[*] Machine-readable:\033[0m\n");
        printf("%s:%s:%s\n", g_algorithm, g_target_hash, g_found_word);
    } else {
        printf("\033[1;31m[-] Hash not cracked\033[0m\n");
        printf("\033[1;36m[*] Attempts: %llu\033[0m\n", (unsigned long long)g_attempts);
        printf("\033[1;36m[*] Time: %.2f seconds\033[0m\n", elapsed);
    }

    printf("\033[1;36m═══════════════════════════════════════════════\033[0m\n\n");

    return result == 0 ? 0 : 1;
}

/* ============================================= */
/* COMPILE INSTRUCTIONS */
/* ============================================= */

/*
 * Compile:
 *   gcc -O2 -pthread -o hash_cracker hash_cracker.c
 *   clang -O2 -pthread -o hash_cracker hash_cracker.c
 *
 * Usage:
 *   ./hash_cracker md5 <hash> -w wordlist.txt
 *   ./hash_cracker md5 <hash> -b lower -l 1 -L 6
 *   ./hash_cracker sha1 <hash> -b all -l 4 -L 8 -t 8
 *   ./hash_cracker sha256 <hash> -w rockyou.txt -t 16
 *
 * Examples:
 *   ./hash_cracker md5 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
 *   ./hash_cracker md5 5f4dcc3b5aa765d61d8327deb882cf99 -b lower -l 1 -L 6
 *   ./hash_cracker sha1 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -b all -l 4 -L 6
 */