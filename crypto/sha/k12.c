/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <internal/thread.h>
#include "internal/sha3.h"


typedef struct k12_st {
    KECCAK1600_CTX trunk;
    KECCAK1600_CTX leaf;
    size_t trunk_bytes;   /* Stops counting at 8192 */
    size_t leaf_bytes;
    size_t CV_count;      /* Number of leaf blocks (chained values) */
    unsigned char* CS;    /* Optional custom string appended to message */
    size_t CS_len;
    OSSL_LIB_CTX *libctx;
} K12_CTX;

typedef struct {
      KECCAK1600_CTX leaf;
      const unsigned char *data;
      unsigned char CV[32];
} K12_THREAD_DATA;

static PROV_SHA3_METHOD turboshake_generic_meth = {
    ossl_turboshake_absorb_default,
    ossl_turboshake_final_default,
    ossl_turboshake_squeeze_default
};

static unsigned char SEPARATOR[8] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static unsigned char FINAL[2] = { 0xFF, 0xFF };

void ossl_k12_reset(K12_CTX *ctx)
{
    ossl_sha3_reset(&ctx->trunk);
    ossl_sha3_reset(&ctx->leaf);
    ctx->CV_count = 0;
    ctx->trunk_bytes = 0;
    ctx->leaf_bytes = 0;
}

/* Absorb data into trunk's KECCAK1600_CTX */
static int k12_absorb_trunk(K12_CTX *ctx, const unsigned char* data, size_t len)
{
    if (ossl_unlikely(len + ctx->trunk_bytes > 8192))
        return 1;

    int ret = ossl_sha3_absorb(&ctx->trunk, data, len);
    ctx->trunk_bytes += len;
    if (ctx->trunk_bytes == 8192) {
        ctx->trunk.pad = 0x06;
        ossl_sha3_absorb(&ctx->trunk, SEPARATOR, sizeof(SEPARATOR));
    }
    return ret;
}

/* Absorb 8192 bytes of data into leaf and squeeze it into CV */
static uint32_t k12_leaf_worker(void *arg)
{
    K12_THREAD_DATA *td = arg;
    ossl_keccak_init(&td->leaf, 0x0B, 128, 32);
    td->leaf.meth = turboshake_generic_meth;

    ossl_sha3_absorb(&td->leaf, td->data, 8192);
    ossl_sha3_squeeze(&td->leaf, td->CV, 32);
    return 0;
}

int ossl_k12_absorb(K12_CTX* ctx, const unsigned char* data, size_t len)
{
    if (ossl_unlikely(len == 0))
        return 1;

    if (ossl_unlikely(!(ctx->trunk.xof_state == XOF_STATE_INIT
                     || ctx->trunk.xof_state == XOF_STATE_ABSORB)))
        return 0;

    /* Absorb until the trunk is filled with 8192 bytes */
    if (ctx->trunk_bytes <= 8192) {
        size_t trunk_remaining = 8192 - ctx->trunk_bytes;
        if (len <= trunk_remaining) {
            return k12_absorb_trunk(ctx, data, len);
        } else {
            k12_absorb_trunk(ctx, data, trunk_remaining);
            len -= trunk_remaining;
            data += trunk_remaining;
        }
    }

    /* Fill the leftover from last absorb first */
    size_t leaf_remaining = 8192 - ctx->leaf_bytes;
    if (len < leaf_remaining) {
        ctx->leaf_bytes += len;
        return ossl_sha3_absorb(&ctx->leaf, data, len);
    } else {
        ossl_sha3_absorb(&ctx->leaf, data, leaf_remaining);
        len -= leaf_remaining;
        data += leaf_remaining;

        /* Leaf is full so squeeze and reset */
        unsigned char CV[32];
        ossl_sha3_squeeze(&ctx->leaf, CV, 32);
        ossl_sha3_absorb(&ctx->trunk, CV, 32);
        ctx->CV_count += 1;

        ossl_sha3_reset(&ctx->leaf);
        ctx->leaf_bytes = 0;
    }

    /* Fill all the full leaf blocks that we can */
    size_t nblocks = len / 8192;
    void **tasks = OPENSSL_calloc(nblocks, sizeof(void *));
    K12_THREAD_DATA *tdata = OPENSSL_calloc(nblocks, sizeof(K12_THREAD_DATA));
    for (size_t i = 0; i < nblocks; i++) {
        tdata[i].data = (const unsigned char *)data + i * 8192;
        tasks[i] = ossl_crypto_thread_start(ctx->libctx, k12_leaf_worker, &tdata[i]);
    }
    for (size_t i = 0; i < nblocks; i++) {
        ossl_crypto_thread_join(tasks[i], NULL);
        ossl_crypto_thread_clean(tasks[i]);
        ossl_sha3_absorb(&ctx->trunk, tdata[i].CV, 32); /* D-value 0x06 */
    }
    OPENSSL_free(tasks);
    OPENSSL_free(tdata);
    ctx->CV_count += nblocks;
    len -= 8192 * nblocks;
    data += 8192 * nblocks;

    /* Fill leftover data in the (already-reset) last leaf and
     * save it for the next absorb instead of making a CV */
    if (len > 0) {
        ctx->leaf_bytes += len;
        ossl_sha3_absorb(&ctx->leaf, data, len);
    }
}

static uint8_t k12_length_encoding(uint64_t x, uint8_t* buf)
{
    /* buf must be 9 bytes! */

    uint8_t tmp[8];
    size_t n = 0;

    while (x > 0) {
        tmp[n++] = x % 256;
        x /= 256;
    }

    /* tmp is little-endian, we want big-endian */
    for (size_t i = 0; i < n; i++)
        buf[i] = tmp[n - 1 - i];

    buf[n] = (uint8_t)n;
    return n + 1;
}

int ossl_k12_final(K12_CTX *ctx, unsigned char *out, size_t outlen)
{
    int ret;

    if (ctx->trunk.xof_state == XOF_STATE_SQUEEZE
        || ctx->trunk.xof_state == XOF_STATE_FINAL)
        return 0;
    if (outlen == 0)
        return 1;

    /* If we have a custom string, absorb CS || length_encoding(|CS|) */
    if (ctx->CS_len > 0) {
        ossl_k12_absorb(ctx, ctx->CS, ctx->CS_len);
        uint8_t buf[9];
        size_t encoding_size = k12_length_encoding(ctx->CS_len, buf);
        ossl_k12_absorb(ctx, buf, encoding_size);
    }

    /* Handle leftovers in leaf ctx and CV_count */
    if (ctx->trunk_bytes >= 8192) {
        unsigned char CV[32];
        ossl_sha3_final(&ctx->leaf, CV, 32);
        ossl_sha3_absorb(&ctx->trunk, CV, 32);
        ctx->CV_count += 1;

        uint8_t buf[9];
        size_t encoding_size = k12_length_encoding(ctx->CV_count, buf);
        ossl_sha3_absorb(&ctx->trunk, buf, encoding_size);

        ossl_sha3_absorb(&ctx->trunk, FINAL, sizeof(FINAL));
    }

    /* The absorb method has already set the padding to 0x06 if necessary */
    ret = ossl_sha3_final(&ctx->trunk, out, outlen);

    return ret;
}


int ossl_k12_squeeze(K12_CTX *ctx, unsigned char *out, size_t outlen)
{
    int ret = 0;

    if (ctx->trunk.xof_state == XOF_STATE_FINAL)
        return 0;

    if (ctx->trunk.xof_state != XOF_STATE_SQUEEZE) {
        /* If we have a custom string, absorb CS || length_encoding(|CS|) */
        if (ctx->CS_len > 0) {
            ossl_k12_absorb(ctx, ctx->CS, ctx->CS_len);
            uint8_t buf[9];
            size_t encoding_size = k12_length_encoding(ctx->CS_len, buf);
            ossl_k12_absorb(ctx, buf, encoding_size);
        }

        /* Handle leftovers in leaf ctx and CV_count */
        if (ctx->trunk_bytes >= 8192) {
            unsigned char CV[32];
            ossl_sha3_final(&ctx->leaf, CV, 32);
            ossl_sha3_absorb(&ctx->trunk, CV, 32);
            ctx->CV_count += 1;

            uint8_t buf[9];
            size_t encoding_size = k12_length_encoding(ctx->CV_count, buf);
            ossl_sha3_absorb(&ctx->trunk, buf, encoding_size);

            ossl_sha3_absorb(&ctx->trunk, FINAL, sizeof(FINAL));
        }
    }

    /* The absorb method has already set the padding to 0x07 if necessary */
    ret = ossl_sha3_squeeze(&ctx->trunk, out, outlen);

    return ret;
}
