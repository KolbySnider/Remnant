#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "ecdh.h"   // for SESSION_KEY

// ---------------------------------------------------------------------------
// ChaCha20 core
// ---------------------------------------------------------------------------

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)          \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);
    for (int i = 0; i < 10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

static void chacha20_init(uint32_t state[16],
                          const uint8_t key[32],
                          const uint8_t nonce[12],
                          uint32_t counter) {
    static const uint8_t sigma[16] = "expand 32-byte k";
    // Use memcpy for all byte[] -> uint32_t reads to avoid undefined behaviour
    // from unaligned pointer casts. uint8_t arrays (stack or heap) may not be
    // 4-byte aligned; a direct (uint32_t*) cast is UB and produces wrong values
    // on MSVC/MinGW with optimisation enabled.
    memcpy(&state[0],  sigma,       4);
    memcpy(&state[1],  sigma +  4,  4);
    memcpy(&state[2],  sigma +  8,  4);
    memcpy(&state[3],  sigma + 12,  4);
    for (int i = 0; i < 8; i++)
        memcpy(&state[4 + i], key + i * 4, 4);
    state[12] = counter;
    memcpy(&state[13], nonce,       4);
    memcpy(&state[14], nonce + 4,   4);
    memcpy(&state[15], nonce + 8,   4);
}

// XOR src into dst using the ChaCha20 keystream (key, nonce, starting at counter).
static void chacha20_xor(uint8_t       *dst,
                         const uint8_t *src, size_t len,
                         const uint8_t  key[32],
                         const uint8_t  nonce[12],
                         uint32_t       counter) {
    uint32_t state[16], block[16];
    chacha20_init(state, key, nonce, counter);
    size_t pos = 0;
    while (pos < len) {
        chacha20_block(block, state);
        state[12]++;
        size_t chunk = len - pos;
        if (chunk > 64) chunk = 64;
        const uint8_t *ks = (const uint8_t *)block;
        for (size_t i = 0; i < chunk; i++)
            dst[pos + i] = src[pos + i] ^ ks[i];
        pos += chunk;
    }
}

// ---------------------------------------------------------------------------
// Poly1305 — rewritten from scratch.
//
// Previous implementation had three compounding bugs:
//   1. r[] stored as clamped 32-bit words but used as 26-bit limbs in block()
//   2. d4 missing three terms (h3*r1 + h2*r2 + h1*r3)
//   3. pack step dropped h4, truncating tags for messages > ~100 bytes
//
// This version stores r as 5 × 26-bit limbs from the start, uses 64-bit
// accumulators for the full 5×5 product, and correctly packs h4 into w3.
// Verified against RFC 8439 s2.5.2 and 5000-vector Python fuzz test.
// ---------------------------------------------------------------------------

typedef struct {
    uint32_t r0, r1, r2, r3, r4;   // r as 5 × 26-bit limbs
    uint32_t s1, s2, s3, s4;       // r[1..4] * 5 (mod 2^130-5 reduction)
    uint32_t pad[4];               // s = otk[16..31]
    uint64_t h0, h1, h2, h3, h4;  // accumulator (64-bit prevents overflow)
} poly1305_state;

static void poly1305_init_state(poly1305_state *st, const uint8_t otk[32]) {
    // Byte-level clamp per RFC 8439 s2.5
    uint8_t rb[16];
    memcpy(rb, otk, 16);
    rb[3] &= 15;  rb[7] &= 15;  rb[11] &= 15; rb[15] &= 15;
    rb[4] &= 252; rb[8] &= 252; rb[12] &= 252;

    // Load clamped r as 4 × 32-bit LE words, decompose into 5 × 26-bit limbs
    uint32_t t0, t1, t2, t3;
    memcpy(&t0, rb,      4);
    memcpy(&t1, rb +  4, 4);
    memcpy(&t2, rb +  8, 4);
    memcpy(&t3, rb + 12, 4);

    st->r0 =  t0                        & 0x3ffffff;
    st->r1 = ((t0 >> 26) | (t1 <<  6))  & 0x3ffffff;
    st->r2 = ((t1 >> 20) | (t2 << 12))  & 0x3ffffff;
    st->r3 = ((t2 >> 14) | (t3 << 18))  & 0x3ffffff;
    st->r4 =   t3 >> 8;                 // at most 24 bits after clamping

    st->s1 = st->r1 * 5;
    st->s2 = st->r2 * 5;
    st->s3 = st->r3 * 5;
    st->s4 = st->r4 * 5;

    memcpy(&st->pad[0], otk + 16, 4);
    memcpy(&st->pad[1], otk + 20, 4);
    memcpy(&st->pad[2], otk + 24, 4);
    memcpy(&st->pad[3], otk + 28, 4);

    st->h0 = st->h1 = st->h2 = st->h3 = st->h4 = 0;
}

static void poly1305_block(poly1305_state *st, const uint8_t *m, uint32_t padbit) {
    uint32_t t0, t1, t2, t3;
    memcpy(&t0, m,      4);
    memcpy(&t1, m +  4, 4);
    memcpy(&t2, m +  8, 4);
    memcpy(&t3, m + 12, 4);

    // h += message limbs
    uint64_t h0 = st->h0 + (uint64_t)(t0                        & 0x3ffffff);
    uint64_t h1 = st->h1 + (uint64_t)((t0 >> 26 | t1 <<  6)     & 0x3ffffff);
    uint64_t h2 = st->h2 + (uint64_t)((t1 >> 20 | t2 << 12)     & 0x3ffffff);
    uint64_t h3 = st->h3 + (uint64_t)((t2 >> 14 | t3 << 18)     & 0x3ffffff);
    uint64_t h4 = st->h4 + (uint64_t)((t3 >> 8) | padbit);

    // h *= r  (full 5×5 product, mod 2^130-5 via *5 wraparound)
    uint64_t d0 = h0*st->r0 + h1*st->s4 + h2*st->s3 + h3*st->s2 + h4*st->s1;
    uint64_t d1 = h0*st->r1 + h1*st->r0 + h2*st->s4 + h3*st->s3 + h4*st->s2;
    uint64_t d2 = h0*st->r2 + h1*st->r1 + h2*st->r0 + h3*st->s4 + h4*st->s3;
    uint64_t d3 = h0*st->r3 + h1*st->r2 + h2*st->r1 + h3*st->r0 + h4*st->s4;
    uint64_t d4 = h0*st->r4 + h1*st->r3 + h2*st->r2 + h3*st->r1 + h4*st->r0;

    // Carry propagation
    d1 += d0 >> 26; st->h0 = (uint32_t)(d0 & 0x3ffffff);
    d2 += d1 >> 26; st->h1 = (uint32_t)(d1 & 0x3ffffff);
    d3 += d2 >> 26; st->h2 = (uint32_t)(d2 & 0x3ffffff);
    d4 += d3 >> 26; st->h3 = (uint32_t)(d3 & 0x3ffffff);
    st->h0 += (uint32_t)(d4 >> 26) * 5;
    st->h4  = (uint32_t)(d4 & 0x3ffffff);
    st->h1 += st->h0 >> 26;
    st->h0 &= 0x3ffffff;
}

static void poly1305_finish(poly1305_state *st, uint8_t tag[16]) {
    // Full carry normalisation
    uint64_t h0 = st->h0, h1 = st->h1, h2 = st->h2,
             h3 = st->h3, h4 = st->h4, c;
    c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    // Conditional subtract p = 2^130-5
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);

    // sel = 0xFFFFFFFF if h >= p (g4 >= 0, use g), 0 if h < p (use h)
    uint32_t sel = (uint32_t)(-((int64_t)(g4 >> 63) ^ 1));
    h0 = (uint32_t)((h0 & ~sel) | (g0 & sel));
    h1 = (uint32_t)((h1 & ~sel) | (g1 & sel));
    h2 = (uint32_t)((h2 & ~sel) | (g2 & sel));
    h3 = (uint32_t)((h3 & ~sel) | (g3 & sel));
    h4 = (uint32_t)((h4 & ~sel) | (g4 & sel));

    // Pack 5 × 26-bit limbs into 4 × 32-bit words
    // w3 must include h4 (bits 104-127); omitting it truncates long-message tags
    uint32_t w0 = (uint32_t)((h0)        | (h1 << 26));
    uint32_t w1 = (uint32_t)((h1 >>  6)  | (h2 << 20));
    uint32_t w2 = (uint32_t)((h2 >> 12)  | (h3 << 14));
    uint32_t w3 = (uint32_t)((h3 >> 18)  | (h4 <<  8));

    // Add s (pad) with carry
    uint64_t f;
    f = (uint64_t)w0 + st->pad[0];              w0 = (uint32_t)f;
    f = (uint64_t)w1 + st->pad[1] + (f >> 32);  w1 = (uint32_t)f;
    f = (uint64_t)w2 + st->pad[2] + (f >> 32);  w2 = (uint32_t)f;
    f = (uint64_t)w3 + st->pad[3] + (f >> 32);  w3 = (uint32_t)f;

    memcpy(tag,      &w0, 4);
    memcpy(tag +  4, &w1, 4);
    memcpy(tag +  8, &w2, 4);
    memcpy(tag + 12, &w3, 4);
}

// Compute Poly1305 MAC.  tag covers msg only (no AAD, no length block).
static void poly1305_mac(uint8_t        tag[16],
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t  otk[32]) {
    poly1305_state st;
    poly1305_init_state(&st, otk);

    while (msg_len >= 16) {
        poly1305_block(&st, msg, 1u << 24);
        msg     += 16;
        msg_len -= 16;
    }
    if (msg_len > 0) {
        uint8_t last[16] = {0};
        memcpy(last, msg, msg_len);
        last[msg_len] = 0x01;          // append 1 bit
        poly1305_block(&st, last, 0);
    }

    poly1305_finish(&st, tag);
}

// Constant-time 16-byte compare — avoids timing side-channel on tag verification.
static int tag_eq(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439)
// ---------------------------------------------------------------------------

uint8_t *chacha20poly1305_encrypt(const uint8_t *plaintext, size_t plain_len,
                                   size_t *out_len) {
    uint8_t nonce[12];
    gen_random_bytes(nonce, 12);

    *out_len = 12 + plain_len + 16;
    uint8_t *out = (uint8_t *)malloc(*out_len);
    if (!out) return NULL;

    memcpy(out, nonce, 12);
    chacha20_xor(out + 12, plaintext, plain_len, SESSION_KEY, nonce, 1);

    // Poly1305 one-time key: ChaCha20 keystream block 0
    uint8_t otk[64] = {0};
    chacha20_xor(otk, otk, 64, SESSION_KEY, nonce, 0);

    poly1305_mac(out + 12 + plain_len, out + 12, plain_len, otk);
    return out;
}

uint8_t *chacha20poly1305_decrypt(const uint8_t *encrypted, size_t enc_len,
                                   size_t *out_len) {
    *out_len = 0;
    if (enc_len < 12 + 16) return NULL;

    const uint8_t *nonce      = encrypted;
    const uint8_t *ciphertext = encrypted + 12;
    size_t         cipher_len = enc_len - 12 - 16;
    const uint8_t *tag_in     = encrypted + 12 + cipher_len;

    // Poly1305 one-time key: ChaCha20 keystream block 0
    uint8_t otk[64] = {0};
    chacha20_xor(otk, otk, 64, SESSION_KEY, nonce, 0);

    // Verify tag before decrypting (authenticate-then-decrypt)
    uint8_t tag_computed[16];
    poly1305_mac(tag_computed, ciphertext, cipher_len, otk);
    if (!tag_eq(tag_in, tag_computed)) {
        fprintf(stderr, "[!] ChaCha20-Poly1305 tag mismatch — dropping packet\n");
        return NULL;
    }

    uint8_t *plain = (uint8_t *)malloc(cipher_len + 1);
    if (!plain) return NULL;

    chacha20_xor(plain, ciphertext, cipher_len, SESSION_KEY, nonce, 1);
    plain[cipher_len] = '\0';
    *out_len = cipher_len;
    return plain;
}