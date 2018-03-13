/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"
#include "uCurve.h"


#if (defined(_WIN32) || defined(_WIN64))
/* Windows */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

int default_RNG(uint8_t *dest, unsigned size) {
    HCRYPTPROV prov;
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return 0;
    }

    CryptGenRandom(prov, size, (BYTE *)dest);
    CryptReleaseContext(prov, 0);
    return 1;
}

#elif defined(unix) || defined(__linux__) || defined(__unix__) || defined(__unix) || \
    (defined(__APPLE__) && defined(__MACH__)) || defined(uECC_POSIX)

/* Some POSIX-like system with /dev/urandom or /dev/random. */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
    #define O_CLOEXEC 0
#endif

int default_RNG(uint8_t *dest, unsigned size) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            return 0;
        }
    }

    char *ptr = (char *)dest;
    size_t left = size;
    while (left > 0) {
        ssize_t bytes_read = read(fd, ptr, left);
        if (bytes_read <= 0) { // read failed
            close(fd);
            return 0;
        }
        left -= bytes_read;
        ptr += bytes_read;
    }

    close(fd);
    return 1;
}

#else /* Some other platform */

int default_RNG(uint8_t *dest, unsigned size) {
    return 0;
}

#endif

uECC_RNG_Function g_rng_function = &default_RNG;

void uECC_set_rng(uECC_RNG_Function rng_function) {
    g_rng_function = rng_function;
}

#ifdef __GNUC__ /* Only support GCC inline asm for now */
    #if (uECC_ASM && (uECC_PLATFORM == uECC_avr))
        #include "asm_avr.inc"
    #endif

    #if (uECC_ASM && (uECC_PLATFORM == uECC_arm || uECC_PLATFORM == uECC_arm_thumb || \
                      uECC_PLATFORM == uECC_arm_thumb2))
        #include "asm_arm.inc"
    #endif
#endif

#if !asm_clear
void vli_clear(uECC_word_t *vli) {
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        vli[i] = 0;
    }
}
#endif

/* Returns 1 if vli == 0, 0 otherwise. */
#if !asm_isZero
uECC_word_t vli_isZero(const uECC_word_t *vli) {
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        if (vli[i]) {
            return 0;
        }
    }
    return 1;
}
#endif

/* Returns nonzero if bit 'bit' of vli is set. */
#if !asm_testBit
uECC_word_t vli_testBit(const uECC_word_t *vli, bitcount_t bit) {
    return (vli[bit >> uECC_WORD_BITS_SHIFT] & ((uECC_word_t)1 << (bit & uECC_WORD_BITS_MASK)));
}
#endif

/* Counts the number of words in vli. */
#if !asm_numBits
wordcount_t vli_numDigits(const uECC_word_t *vli, wordcount_t max_words) {
    swordcount_t i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for (i = max_words - 1; i >= 0 && vli[i] == 0; --i) {
    }

    return (i + 1);
}

/* Counts the number of bits required to represent vli. */
bitcount_t vli_numBits(const uECC_word_t *vli, wordcount_t max_words) {
    uECC_word_t i;
    uECC_word_t digit;

    wordcount_t num_digits = vli_numDigits(vli, max_words);
    if (num_digits == 0) {
        return 0;
    }

    digit = vli[num_digits - 1];
    for (i = 0; digit; ++i) {
        digit >>= 1;
    }

    return (((bitcount_t)(num_digits - 1) << uECC_WORD_BITS_SHIFT) + i);
}
#endif /* !asm_numBits */

/* Sets dest = src. */
#if !asm_set
void vli_set(uECC_word_t *dest, const uECC_word_t *src) {
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        dest[i] = src[i];
    }
}
#endif

/* Returns sign of left - right. */
#if !asm_cmp
cmpresult_t vli_cmp(const uECC_word_t *left, const uECC_word_t *right) {
    swordcount_t i;
    for (i = uECC_WORDS - 1; i >= 0; --i) {
        if (left[i] > right[i]) {
            return 1;
        } else if (left[i] < right[i]) {
            return -1;
        }
    }
    return 0;
}
#endif

cmpresult_t vli_equal(const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t result = 0;
    swordcount_t i;
    for (i = uECC_WORDS - 1; i >= 0; --i) {
        result |= (left[i] ^ right[i]);
    }
    return (result == 0);
}

/* Computes vli = vli >> 1. */
#if !asm_rshift1
void vli_rshift1(uECC_word_t *vli) {
    uECC_word_t *end = vli;
    uECC_word_t carry = 0;

    vli += uECC_WORDS;
    while (vli-- > end) {
        uECC_word_t temp = *vli;
        *vli = (temp >> 1) | carry;
        carry = temp << (uECC_WORD_BITS - 1);
    }
}
#endif

/* Computes result = left + right, returning carry. Can modify in place. */
#if !asm_add
uECC_word_t vli_add(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t carry = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uECC_word_t sum = left[i] + right[i] + carry;
        if (sum != left[i]) {
            carry = (sum < left[i]);
        }
        result[i] = sum;
    }
    return carry;
}
#endif

/* Computes result = left - right, returning borrow. Can modify in place. */
#if !asm_sub
uECC_word_t vli_sub(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}
#endif

#if (!asm_mult || (uECC_SQUARE_FUNC && !asm_square) || uECC_CURVE == uECC_secp256k1)
void muladd(uECC_word_t a,
                   uECC_word_t b,
                   uECC_word_t *r0,
                   uECC_word_t *r1,
                   uECC_word_t *r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1) { // overflow
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}
#define muladd_exists 1
#endif

#if !asm_mult
void vli_mult(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t i, k;

    /* Compute each digit of result in sequence, maintaining the carries. */
    for (k = 0; k < uECC_WORDS; ++k) {
        for (i = 0; i <= k; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    for (k = uECC_WORDS; k < uECC_WORDS * 2 - 1; ++k) {
        for (i = (k + 1) - uECC_WORDS; i < uECC_WORDS; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_WORDS * 2 - 1] = r0;
}
#endif

#if uECC_SQUARE_FUNC

#if !asm_square
void mul2add(uECC_word_t a,
                    uECC_word_t b,
                    uECC_word_t *r0,
                    uECC_word_t *r1,
                    uECC_word_t *r2) {
#if uECC_WORD_SIZE == 8 && !SUPPORTS_INT128
    uint64_t a0 = a & 0xffffffffull;
    uint64_t a1 = a >> 32;
    uint64_t b0 = b & 0xffffffffull;
    uint64_t b1 = b >> 32;

    uint64_t i0 = a0 * b0;
    uint64_t i1 = a0 * b1;
    uint64_t i2 = a1 * b0;
    uint64_t i3 = a1 * b1;

    uint64_t p0, p1;

    i2 += (i0 >> 32);
    i2 += i1;
    if (i2 < i1)
    { // overflow
        i3 += 0x100000000ull;
    }

    p0 = (i0 & 0xffffffffull) | (i2 << 32);
    p1 = i3 + (i2 >> 32);

    *r2 += (p1 >> 63);
    p1 = (p1 << 1) | (p0 >> 63);
    p0 <<= 1;

    *r0 += p0;
    *r1 += (p1 + (*r0 < p0));
    *r2 += ((*r1 < p1) || (*r1 == p1 && *r0 < p0));
#else
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    *r2 += (p >> (uECC_WORD_BITS * 2 - 1));
    p *= 2;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
#endif
}

void vli_square(uECC_word_t *result, const uECC_word_t *left) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;

    wordcount_t i, k;

    for (k = 0; k < uECC_WORDS * 2 - 1; ++k) {
        uECC_word_t min = (k < uECC_WORDS ? 0 : (k + 1) - uECC_WORDS);
        for (i = min; i <= k && i <= k - i; ++i) {
            if (i < k-i) {
                mul2add(left[i], left[k - i], &r0, &r1, &r2);
            } else {
                muladd(left[i], left[k - i], &r0, &r1, &r2);
            }
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }

    result[uECC_WORDS * 2 - 1] = r0;
}
#endif

#else /* uECC_SQUARE_FUNC */

#define vli_square(result, left, size) vli_mult((result), (left), (left), (size))

#endif /* uECC_SQUARE_FUNC */


/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
#if !asm_modAdd
void vli_modAdd(uECC_word_t *result,
                       const uECC_word_t *left,
                       const uECC_word_t *right,
                       const uECC_word_t *mod) {
    uECC_word_t carry = vli_add(result, left, right);
    if (carry || vli_cmp(result, mod) >= 0) {
        /* result > mod (result = mod + remainder), so subtract mod to get remainder. */
        vli_sub(result, result, mod);
    }
}
#endif

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, and that result does not overlap mod. */
#if !asm_modSub
void vli_modSub(uECC_word_t *result,
                       const uECC_word_t *left,
                       const uECC_word_t *right,
                       const uECC_word_t *mod) {
    uECC_word_t l_borrow = vli_sub(result, left, right);
    if (l_borrow) {
        /* In this case, result == -diff == (max int) - diff. Since -x % d == d - x,
           we can get the correct result from result + mod (with overflow). */
        vli_add(result, result, mod);
    }
}
#endif

#if !asm_modSub_fast
    #define vli_modSub_fast(result, left, right) vli_modSub((result), (left), (right), curve_p)
#endif

#if !asm_mmod_fast

#if (uECC_CURVE == uECC_secp160r1 || uECC_CURVE == uECC_secp256k1)
/* omega_mult() is defined farther below for the different curves / word sizes */
void omega_mult(uECC_word_t * RESTRICT result, const uECC_word_t * RESTRICT right);

/* Computes result = product % curve_p
    see http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf page 354

    Note that this only works if log2(omega) < log2(p) / 2 */
void vli_mmod_fast(uECC_word_t *RESTRICT result, uECC_word_t *RESTRICT product) {
    uECC_word_t tmp[2 * uECC_WORDS];
    uECC_word_t carry;

    vli_clear(tmp);
    vli_clear(tmp + uECC_WORDS);

    omega_mult(tmp, product + uECC_WORDS); /* (Rq, q) = q * c */

    carry = vli_add(result, product, tmp); /* (C, r) = r + q       */
    vli_clear(product);
    omega_mult(product, tmp + uECC_WORDS); /* Rq*c */
    carry += vli_add(result, result, product); /* (C1, r) = r + Rq*c */

    while (carry > 0) {
        --carry;
        vli_sub(result, result, curve_p);
    }
    if (vli_cmp(result, curve_p) > 0) {
        vli_sub(result, result, curve_p);
    }
}

#endif

#if uECC_CURVE == uECC_secp160r1

#if uECC_WORD_SIZE == 1
void omega_mult(uint8_t * RESTRICT result, const uint8_t * RESTRICT right) {
    uint8_t carry;
    uint8_t i;

    /* Multiply by (2^31 + 1). */
    vli_set(result + 4, right); /* 2^32 */
    vli_rshift1(result + 4); /* 2^31 */
    result[3] = right[0] << 7; /* get last bit from shift */

    carry = vli_add(result, result, right); /* 2^31 + 1 */
    for (i = uECC_WORDS; carry; ++i) {
        uint16_t sum = (uint16_t)result[i] + carry;
        result[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
}
#elif uECC_WORD_SIZE == 4
void omega_mult(uint32_t * RESTRICT result, const uint32_t * RESTRICT right) {
    uint32_t carry;
    unsigned i;

    /* Multiply by (2^31 + 1). */
    vli_set(result + 1, right); /* 2^32 */
    vli_rshift1(result + 1); /* 2^31 */
    result[0] = right[0] << 31; /* get last bit from shift */

    carry = vli_add(result, result, right); /* 2^31 + 1 */
    for (i = uECC_WORDS; carry; ++i) {
        uint64_t sum = (uint64_t)result[i] + carry;
        result[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp192r1

/* Computes result = product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
#if uECC_WORD_SIZE == 1
void vli_mmod_fast(uint8_t *RESTRICT result, uint8_t *RESTRICT product) {
    uint8_t tmp[uECC_WORDS];
    uint8_t carry;

    vli_set(result, product);

    vli_set(tmp, &product[24]);
    carry = vli_add(result, result, tmp);

    tmp[0] = tmp[1] = tmp[2] = tmp[3] = tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    tmp[8] = product[24]; tmp[9] = product[25]; tmp[10] = product[26]; tmp[11] = product[27];
    tmp[12] = product[28]; tmp[13] = product[29]; tmp[14] = product[30]; tmp[15] = product[31];
    tmp[16] = product[32]; tmp[17] = product[33]; tmp[18] = product[34]; tmp[19] = product[35];
    tmp[20] = product[36]; tmp[21] = product[37]; tmp[22] = product[38]; tmp[23] = product[39];
    carry += vli_add(result, result, tmp);

    tmp[0] = tmp[8] = product[40];
    tmp[1] = tmp[9] = product[41];
    tmp[2] = tmp[10] = product[42];
    tmp[3] = tmp[11] = product[43];
    tmp[4] = tmp[12] = product[44];
    tmp[5] = tmp[13] = product[45];
    tmp[6] = tmp[14] = product[46];
    tmp[7] = tmp[15] = product[47];
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    carry += vli_add(result, result, tmp);

    while (carry || vli_cmp(curve_p, result) != 1) {
        carry -= vli_sub(result, result, curve_p);
    }
}
#elif uECC_WORD_SIZE == 4
void vli_mmod_fast(uint32_t *RESTRICT result, uint32_t *RESTRICT product) {
    uint32_t tmp[uECC_WORDS];
    int carry;

    vli_set(result, product);

    vli_set(tmp, &product[6]);
    carry = vli_add(result, result, tmp);

    tmp[0] = tmp[1] = 0;
    tmp[2] = product[6];
    tmp[3] = product[7];
    tmp[4] = product[8];
    tmp[5] = product[9];
    carry += vli_add(result, result, tmp);

    tmp[0] = tmp[2] = product[10];
    tmp[1] = tmp[3] = product[11];
    tmp[4] = tmp[5] = 0;
    carry += vli_add(result, result, tmp);

    while (carry || vli_cmp(curve_p, result) != 1) {
        carry -= vli_sub(result, result, curve_p);
    }
}
#else
void vli_mmod_fast(uint64_t *RESTRICT result, uint64_t *RESTRICT product) {
    uint64_t tmp[uECC_WORDS];
    int carry;

    vli_set(result, product);

    vli_set(tmp, &product[3]);
    carry = vli_add(result, result, tmp);

    tmp[0] = 0;
    tmp[1] = product[3];
    tmp[2] = product[4];
    carry += vli_add(result, result, tmp);

    tmp[0] = tmp[1] = product[5];
    tmp[2] = 0;
    carry += vli_add(result, result, tmp);

    while (carry || vli_cmp(curve_p, result) != 1) {
        carry -= vli_sub(result, result, curve_p);
    }
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp256r1

/* Computes result = product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
#if uECC_WORD_SIZE == 1
void vli_mmod_fast(uint8_t *RESTRICT result, uint8_t *RESTRICT product) {
    uint8_t tmp[uECC_BYTES];
    int8_t carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    tmp[8] = tmp[9] = tmp[10] = tmp[11] = 0;
    tmp[12] = product[44]; tmp[13] = product[45]; tmp[14] = product[46]; tmp[15] = product[47];
    tmp[16] = product[48]; tmp[17] = product[49]; tmp[18] = product[50]; tmp[19] = product[51];
    tmp[20] = product[52]; tmp[21] = product[53]; tmp[22] = product[54]; tmp[23] = product[55];
    tmp[24] = product[56]; tmp[25] = product[57]; tmp[26] = product[58]; tmp[27] = product[59];
    tmp[28] = product[60]; tmp[29] = product[61]; tmp[30] = product[62]; tmp[31] = product[63];
    carry = vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s2 */
    tmp[12] = product[48]; tmp[13] = product[49]; tmp[14] = product[50]; tmp[15] = product[51];
    tmp[16] = product[52]; tmp[17] = product[53]; tmp[18] = product[54]; tmp[19] = product[55];
    tmp[20] = product[56]; tmp[21] = product[57]; tmp[22] = product[58]; tmp[23] = product[59];
    tmp[24] = product[60]; tmp[25] = product[61]; tmp[26] = product[62]; tmp[27] = product[63];
    tmp[28] = tmp[29] = tmp[30] = tmp[31] = 0;
    carry += vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s3 */
    tmp[0] = product[32]; tmp[1] = product[33]; tmp[2] = product[34]; tmp[3] = product[35];
    tmp[4] = product[36]; tmp[5] = product[37]; tmp[6] = product[38]; tmp[7] = product[39];
    tmp[8] = product[40]; tmp[9] = product[41]; tmp[10] = product[42]; tmp[11] = product[43];
    tmp[12] = tmp[13] = tmp[14] = tmp[15] = 0;
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = product[56]; tmp[25] = product[57]; tmp[26] = product[58]; tmp[27] = product[59];
    tmp[28] = product[60]; tmp[29] = product[61]; tmp[30] = product[62]; tmp[31] = product[63];
    carry += vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = product[36]; tmp[1] = product[37]; tmp[2] = product[38]; tmp[3] = product[39];
    tmp[4] = product[40]; tmp[5] = product[41]; tmp[6] = product[42]; tmp[7] = product[43];
    tmp[8] = product[44]; tmp[9] = product[45]; tmp[10] = product[46]; tmp[11] = product[47];
    tmp[12] = product[52]; tmp[13] = product[53]; tmp[14] = product[54]; tmp[15] = product[55];
    tmp[16] = product[56]; tmp[17] = product[57]; tmp[18] = product[58]; tmp[19] = product[59];
    tmp[20] = product[60]; tmp[21] = product[61]; tmp[22] = product[62]; tmp[23] = product[63];
    tmp[24] = product[52]; tmp[25] = product[53]; tmp[26] = product[54]; tmp[27] = product[55];
    tmp[28] = product[32]; tmp[29] = product[33]; tmp[30] = product[34]; tmp[31] = product[35];
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[44]; tmp[1] = product[45]; tmp[2] = product[46]; tmp[3] = product[47];
    tmp[4] = product[48]; tmp[5] = product[49]; tmp[6] = product[50]; tmp[7] = product[51];
    tmp[8] = product[52]; tmp[9] = product[53]; tmp[10] = product[54]; tmp[11] = product[55];
    tmp[12] = tmp[13] = tmp[14] = tmp[15] = 0;
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = product[32]; tmp[25] = product[33]; tmp[26] = product[34]; tmp[27] = product[35];
    tmp[28] = product[40]; tmp[29] = product[41]; tmp[30] = product[42]; tmp[31] = product[43];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[48]; tmp[1] = product[49]; tmp[2] = product[50]; tmp[3] = product[51];
    tmp[4] = product[52]; tmp[5] = product[53]; tmp[6] = product[54]; tmp[7] = product[55];
    tmp[8] = product[56]; tmp[9] = product[57]; tmp[10] = product[58]; tmp[11] = product[59];
    tmp[12] = product[60]; tmp[13] = product[61]; tmp[14] = product[62]; tmp[15] = product[63];
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = product[36]; tmp[25] = product[37]; tmp[26] = product[38]; tmp[27] = product[39];
    tmp[28] = product[44]; tmp[29] = product[45]; tmp[30] = product[46]; tmp[31] = product[47];
    carry -= vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = product[52]; tmp[1] = product[53]; tmp[2] = product[54]; tmp[3] = product[55];
    tmp[4] = product[56]; tmp[5] = product[57]; tmp[6] = product[58]; tmp[7] = product[59];
    tmp[8] = product[60]; tmp[9] = product[61]; tmp[10] = product[62]; tmp[11] = product[63];
    tmp[12] = product[32]; tmp[13] = product[33]; tmp[14] = product[34]; tmp[15] = product[35];
    tmp[16] = product[36]; tmp[17] = product[37]; tmp[18] = product[38]; tmp[19] = product[39];
    tmp[20] = product[40]; tmp[21] = product[41]; tmp[22] = product[42]; tmp[23] = product[43];
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    tmp[28] = product[48]; tmp[29] = product[49]; tmp[30] = product[50]; tmp[31] = product[51];
    carry -= vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[56]; tmp[1] = product[57]; tmp[2] = product[58]; tmp[3] = product[59];
    tmp[4] = product[60]; tmp[5] = product[61]; tmp[6] = product[62]; tmp[7] = product[63];
    tmp[8] = tmp[9] = tmp[10] = tmp[11] = 0;
    tmp[12] = product[36]; tmp[13] = product[37]; tmp[14] = product[38]; tmp[15] = product[39];
    tmp[16] = product[40]; tmp[17] = product[41]; tmp[18] = product[42]; tmp[19] = product[43];
    tmp[20] = product[44]; tmp[21] = product[45]; tmp[22] = product[46]; tmp[23] = product[47];
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    tmp[28] = product[52]; tmp[29] = product[53]; tmp[30] = product[54]; tmp[31] = product[55];
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    } else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#elif uECC_WORD_SIZE == 4
void vli_mmod_fast(uint32_t *RESTRICT result, uint32_t *RESTRICT product) {
    uint32_t tmp[uECC_WORDS];
    int carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = 0;
    tmp[3] = product[11];
    tmp[4] = product[12];
    tmp[5] = product[13];
    tmp[6] = product[14];
    tmp[7] = product[15];
    carry = vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s2 */
    tmp[3] = product[12];
    tmp[4] = product[13];
    tmp[5] = product[14];
    tmp[6] = product[15];
    tmp[7] = 0;
    carry += vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s3 */
    tmp[0] = product[8];
    tmp[1] = product[9];
    tmp[2] = product[10];
    tmp[3] = tmp[4] = tmp[5] = 0;
    tmp[6] = product[14];
    tmp[7] = product[15];
    carry += vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = product[9];
    tmp[1] = product[10];
    tmp[2] = product[11];
    tmp[3] = product[13];
    tmp[4] = product[14];
    tmp[5] = product[15];
    tmp[6] = product[13];
    tmp[7] = product[8];
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[11];
    tmp[1] = product[12];
    tmp[2] = product[13];
    tmp[3] = tmp[4] = tmp[5] = 0;
    tmp[6] = product[8];
    tmp[7] = product[10];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[12];
    tmp[1] = product[13];
    tmp[2] = product[14];
    tmp[3] = product[15];
    tmp[4] = tmp[5] = 0;
    tmp[6] = product[9];
    tmp[7] = product[11];
    carry -= vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = product[13];
    tmp[1] = product[14];
    tmp[2] = product[15];
    tmp[3] = product[8];
    tmp[4] = product[9];
    tmp[5] = product[10];
    tmp[6] = 0;
    tmp[7] = product[12];
    carry -= vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[14];
    tmp[1] = product[15];
    tmp[2] = 0;
    tmp[3] = product[9];
    tmp[4] = product[10];
    tmp[5] = product[11];
    tmp[6] = 0;
    tmp[7] = product[13];
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    } else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#else
void vli_mmod_fast(uint64_t *RESTRICT result, uint64_t *RESTRICT product) {
    uint64_t tmp[uECC_WORDS];
    int carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = 0;
    tmp[1] = product[5] & 0xffffffff00000000ull;
    tmp[2] = product[6];
    tmp[3] = product[7];
    carry = vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s2 */
    tmp[1] = product[6] << 32;
    tmp[2] = (product[6] >> 32) | (product[7] << 32);
    tmp[3] = product[7] >> 32;
    carry += vli_add(tmp, tmp, tmp);
    carry += vli_add(result, result, tmp);

    /* s3 */
    tmp[0] = product[4];
    tmp[1] = product[5] & 0xffffffff;
    tmp[2] = 0;
    tmp[3] = product[7];
    carry += vli_add(result, result, tmp);

    /* s4 */
    tmp[0] = (product[4] >> 32) | (product[5] << 32);
    tmp[1] = (product[5] >> 32) | (product[6] & 0xffffffff00000000ull);
    tmp[2] = product[7];
    tmp[3] = (product[6] >> 32) | (product[4] << 32);
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = (product[5] >> 32) | (product[6] << 32);
    tmp[1] = (product[6] >> 32);
    tmp[2] = 0;
    tmp[3] = (product[4] & 0xffffffff) | (product[5] << 32);
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[6];
    tmp[1] = product[7];
    tmp[2] = 0;
    tmp[3] = (product[4] >> 32) | (product[5] & 0xffffffff00000000ull);
    carry -= vli_sub(result, result, tmp);

    /* d3 */
    tmp[0] = (product[6] >> 32) | (product[7] << 32);
    tmp[1] = (product[7] >> 32) | (product[4] << 32);
    tmp[2] = (product[4] >> 32) | (product[5] << 32);
    tmp[3] = (product[6] << 32);
    carry -= vli_sub(result, result, tmp);

    /* d4 */
    tmp[0] = product[7];
    tmp[1] = product[4] & 0xffffffff00000000ull;
    tmp[2] = product[5];
    tmp[3] = product[6] & 0xffffffff00000000ull;
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    } else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp256k1

#if uECC_WORD_SIZE == 1
void omega_mult(uint8_t * RESTRICT result, const uint8_t * RESTRICT right) {
    /* Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t k;

    /* Multiply by (2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    muladd(0xD1, right[0], &r0, &r1, &r2);
    result[0] = r0;
    r0 = r1;
    r1 = r2;
    /* r2 is still 0 */

    for (k = 1; k < uECC_WORDS; ++k) {
        muladd(0x03, right[k - 1], &r0, &r1, &r2);
        muladd(0xD1, right[k], &r0, &r1, &r2);
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    muladd(0x03, right[uECC_WORDS - 1], &r0, &r1, &r2);
    result[uECC_WORDS] = r0;
    result[uECC_WORDS + 1] = r1;

    result[4 + uECC_WORDS] = vli_add(result + 4, result + 4, right); /* add the 2^32 multiple */
}
#elif uECC_WORD_SIZE == 4
void omega_mult(uint32_t * RESTRICT result, const uint32_t * RESTRICT right) {
    /* Multiply by (2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    uint32_t carry = 0;
    wordcount_t k;

    for (k = 0; k < uECC_WORDS; ++k) {
        uint64_t p = (uint64_t)0x3D1 * right[k] + carry;
        result[k] = (p & 0xffffffff);
        carry = p >> 32;
    }
    result[uECC_WORDS] = carry;

    result[1 + uECC_WORDS] = vli_add(result + 1, result + 1, right); /* add the 2^32 multiple */
}
#else
void omega_mult(uint64_t * RESTRICT result, const uint64_t * RESTRICT right) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t k;

    /* Multiply by (2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1). */
    for (k = 0; k < uECC_WORDS; ++k) {
        muladd(0x1000003D1ull, right[k], &r0, &r1, &r2);
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_WORDS] = r0;
}
#endif /* uECC_WORD_SIZE */

#elif uECC_CURVE == uECC_secp224r1

/* Computes result = product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
#if uECC_WORD_SIZE == 1
// TODO it may be faster to use the omega_mult method when fully asm optimized.
void vli_mmod_fast(uint8_t *RESTRICT result, uint8_t *RESTRICT product) {
    uint8_t tmp[uECC_WORDS];
    int8_t carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = tmp[3] = 0;
    tmp[4] = tmp[5] = tmp[6] = tmp[7] = 0;
    tmp[8] = tmp[9] = tmp[10] = tmp[11] = 0;
    tmp[12] = product[28]; tmp[13] = product[29]; tmp[14] = product[30]; tmp[15] = product[31];
    tmp[16] = product[32]; tmp[17] = product[33]; tmp[18] = product[34]; tmp[19] = product[35];
    tmp[20] = product[36]; tmp[21] = product[37]; tmp[22] = product[38]; tmp[23] = product[39];
    tmp[24] = product[40]; tmp[25] = product[41]; tmp[26] = product[42]; tmp[27] = product[43];
    carry = vli_add(result, result, tmp);

    /* s2 */
    tmp[12] = product[44]; tmp[13] = product[45]; tmp[14] = product[46]; tmp[15] = product[47];
    tmp[16] = product[48]; tmp[17] = product[49]; tmp[18] = product[50]; tmp[19] = product[51];
    tmp[20] = product[52]; tmp[21] = product[53]; tmp[22] = product[54]; tmp[23] = product[55];
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0]  = product[28]; tmp[1]  = product[29]; tmp[2]  = product[30]; tmp[3]  = product[31];
    tmp[4]  = product[32]; tmp[5]  = product[33]; tmp[6]  = product[34]; tmp[7]  = product[35];
    tmp[8]  = product[36]; tmp[9]  = product[37]; tmp[10] = product[38]; tmp[11] = product[39];
    tmp[12] = product[40]; tmp[13] = product[41]; tmp[14] = product[42]; tmp[15] = product[43];
    tmp[16] = product[44]; tmp[17] = product[45]; tmp[18] = product[46]; tmp[19] = product[47];
    tmp[20] = product[48]; tmp[21] = product[49]; tmp[22] = product[50]; tmp[23] = product[51];
    tmp[24] = product[52]; tmp[25] = product[53]; tmp[26] = product[54]; tmp[27] = product[55];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0]  = product[44]; tmp[1]  = product[45]; tmp[2]  = product[46]; tmp[3]  = product[47];
    tmp[4]  = product[48]; tmp[5]  = product[49]; tmp[6]  = product[50]; tmp[7]  = product[51];
    tmp[8]  = product[52]; tmp[9]  = product[53]; tmp[10] = product[54]; tmp[11] = product[55];
    tmp[12] = tmp[13] = tmp[14] = tmp[15] = 0;
    tmp[16] = tmp[17] = tmp[18] = tmp[19] = 0;
    tmp[20] = tmp[21] = tmp[22] = tmp[23] = 0;
    tmp[24] = tmp[25] = tmp[26] = tmp[27] = 0;
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    } else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#elif uECC_WORD_SIZE == 4
void vli_mmod_fast(uint32_t *RESTRICT result, uint32_t *RESTRICT product)
{
    uint32_t tmp[uECC_WORDS];
    int carry;

    /* t */
    vli_set(result, product);

    /* s1 */
    tmp[0] = tmp[1] = tmp[2] = 0;
    tmp[3] = product[7];
    tmp[4] = product[8];
    tmp[5] = product[9];
    tmp[6] = product[10];
    carry = vli_add(result, result, tmp);

    /* s2 */
    tmp[3] = product[11];
    tmp[4] = product[12];
    tmp[5] = product[13];
    tmp[6] = 0;
    carry += vli_add(result, result, tmp);

    /* d1 */
    tmp[0] = product[7];
    tmp[1] = product[8];
    tmp[2] = product[9];
    tmp[3] = product[10];
    tmp[4] = product[11];
    tmp[5] = product[12];
    tmp[6] = product[13];
    carry -= vli_sub(result, result, tmp);

    /* d2 */
    tmp[0] = product[11];
    tmp[1] = product[12];
    tmp[2] = product[13];
    tmp[3] = tmp[4] = tmp[5] = tmp[6] = 0;
    carry -= vli_sub(result, result, tmp);

    if (carry < 0) {
        do {
            carry += vli_add(result, result, curve_p);
        } while (carry < 0);
    } else {
        while (carry || vli_cmp(curve_p, result) != 1) {
            carry -= vli_sub(result, result, curve_p);
        }
    }
}
#endif /* uECC_WORD_SIZE */

#endif /* uECC_CURVE */
#endif /* !asm_mmod_fast */

/* Computes result = (left * right) % curve_p. */
void vli_modMult_fast(uECC_word_t *result,
                             const uECC_word_t *left,
                             const uECC_word_t *right) {
    uECC_word_t product[2 * uECC_WORDS];
    vli_mult(product, left, right);
    vli_mmod_fast(result, product);
}

#if uECC_SQUARE_FUNC

/* Computes result = left^2 % curve_p. */
void vli_modSquare_fast(uECC_word_t *result, const uECC_word_t *left) {
    uECC_word_t product[2 * uECC_WORDS];
    vli_square(product, left);
    vli_mmod_fast(result, product);
}

#else /* uECC_SQUARE_FUNC */

#define vli_modSquare_fast(result, left) vli_modMult_fast((result), (left), (left))

#endif /* uECC_SQUARE_FUNC */


#define EVEN(vli) (!(vli[0] & 1))
/* Computes result = (1 / input) % mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
#if !asm_modInv
void vli_modInv(uECC_word_t *result, const uECC_word_t *input, const uECC_word_t *mod) {
    uECC_word_t a[uECC_WORDS], b[uECC_WORDS], u[uECC_WORDS], v[uECC_WORDS];
    uECC_word_t carry;
    cmpresult_t cmpResult;

    if (vli_isZero(input)) {
        vli_clear(result);
        return;
    }

    vli_set(a, input);
    vli_set(b, mod);
    vli_clear(u);
    u[0] = 1;
    vli_clear(v);
    while ((cmpResult = vli_cmp(a, b)) != 0) {
        carry = 0;
        if (EVEN(a)) {
            vli_rshift1(a);
            if (!EVEN(u)) {
                carry = vli_add(u, u, mod);
            }
            vli_rshift1(u);
            if (carry) {
                u[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else if (EVEN(b)) {
            vli_rshift1(b);
            if (!EVEN(v)) {
                carry = vli_add(v, v, mod);
            }
            vli_rshift1(v);
            if (carry) {
                v[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else if (cmpResult > 0) {
            vli_sub(a, a, b);
            vli_rshift1(a);
            if (vli_cmp(u, v) < 0) {
                vli_add(u, u, mod);
            }
            vli_sub(u, u, v);
            if (!EVEN(u)) {
                carry = vli_add(u, u, mod);
            }
            vli_rshift1(u);
            if (carry) {
                u[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else {
            vli_sub(b, b, a);
            vli_rshift1(b);
            if (vli_cmp(v, u) < 0) {
                vli_add(v, v, mod);
            }
            vli_sub(v, v, u);
            if (!EVEN(v)) {
                carry = vli_add(v, v, mod);
            }
            vli_rshift1(v);
            if (carry) {
                v[uECC_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
    }
    vli_set(result, u);
}
#endif /* !asm_modInv */

/* ------ Point operations ------ */

/* Returns 1 if 'point' is the point at infinity, 0 otherwise. */
cmpresult_t EccPoint_isZero(const EccPoint *point) {
    return (vli_isZero(point->x) && vli_isZero(point->y));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
#if (uECC_CURVE == uECC_secp256k1)
void EccPoint_double_jacobian(uECC_word_t * RESTRICT X1,
                                     uECC_word_t * RESTRICT Y1,
                                     uECC_word_t * RESTRICT Z1) {
    /* t1 = X, t2 = Y, t3 = Z */
    uECC_word_t t4[uECC_WORDS];
    uECC_word_t t5[uECC_WORDS];

    if (vli_isZero(Z1)) {
        return;
    }

    vli_modSquare_fast(t5, Y1);   /* t5 = y1^2 */
    vli_modMult_fast(t4, X1, t5); /* t4 = x1*y1^2 = A */
    vli_modSquare_fast(X1, X1);   /* t1 = x1^2 */
    vli_modSquare_fast(t5, t5);   /* t5 = y1^4 */
    vli_modMult_fast(Z1, Y1, Z1); /* t3 = y1*z1 = z3 */

    vli_modAdd(Y1, X1, X1, curve_p); /* t2 = 2*x1^2 */
    vli_modAdd(Y1, Y1, X1, curve_p); /* t2 = 3*x1^2 */
    if (vli_testBit(Y1, 0)) {
        uECC_word_t carry = vli_add(Y1, Y1, curve_p);
        vli_rshift1(Y1);
        Y1[uECC_WORDS - 1] |= carry << (uECC_WORD_BITS - 1);
    } else {
        vli_rshift1(Y1);
    }
    /* t2 = 3/2*(x1^2) = B */

    vli_modSquare_fast(X1, Y1);      /* t1 = B^2 */
    vli_modSub(X1, X1, t4, curve_p); /* t1 = B^2 - A */
    vli_modSub(X1, X1, t4, curve_p); /* t1 = B^2 - 2A = x3 */

    vli_modSub(t4, t4, X1, curve_p); /* t4 = A - x3 */
    vli_modMult_fast(Y1, Y1, t4);    /* t2 = B * (A - x3) */
    vli_modSub(Y1, Y1, t5, curve_p); /* t2 = B * (A - x3) - y1^4 = y3 */
}
#else
void EccPoint_double_jacobian(uECC_word_t * RESTRICT X1,
                                     uECC_word_t * RESTRICT Y1,
                                     uECC_word_t * RESTRICT Z1) {
    /* t1 = X, t2 = Y, t3 = Z */
    uECC_word_t t4[uECC_WORDS];
    uECC_word_t t5[uECC_WORDS];

    if (vli_isZero(Z1)) {
        return;
    }

    vli_modSquare_fast(t4, Y1);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1);   /* t3 = z1^2 */

    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve_p); /* t3 = 2*z1^2 */
    vli_modSub_fast(Z1, X1, Z1);     /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1);    /* t1 = x1^2 - z1^4 */

    vli_modAdd(Z1, X1, X1, curve_p); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve_p); /* t1 = 3*(x1^2 - z1^4) */
    if (vli_testBit(X1, 0)) {
        uECC_word_t l_carry = vli_add(X1, X1, curve_p);
        vli_rshift1(X1);
        X1[uECC_WORDS - 1] |= l_carry << (uECC_WORD_BITS - 1);
    } else {
        vli_rshift1(X1);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */

    vli_modSquare_fast(Z1, X1);   /* t3 = B^2 */
    vli_modSub_fast(Z1, Z1, t5);  /* t3 = B^2 - A */
    vli_modSub_fast(Z1, Z1, t5);  /* t3 = B^2 - 2A = x3 */
    vli_modSub_fast(t5, t5, Z1);  /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5); /* t1 = B * (A - x3) */
    vli_modSub_fast(t4, X1, t4);  /* t4 = B * (A - x3) - y1^4 = y3 */

    vli_set(X1, Z1);
    vli_set(Z1, Y1);
    vli_set(Y1, t4);
}
#endif



/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
void apply_z(uECC_word_t * RESTRICT X1,
                    uECC_word_t * RESTRICT Y1,
                    const uECC_word_t * RESTRICT Z) {
    uECC_word_t t1[uECC_WORDS];

    vli_modSquare_fast(t1, Z);    /* z^2 */
    vli_modMult_fast(X1, X1, t1); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
void XYcZ_initial_double(uECC_word_t * RESTRICT X1,
                                uECC_word_t * RESTRICT Y1,
                                uECC_word_t * RESTRICT X2,
                                uECC_word_t * RESTRICT Y2,
                                const uECC_word_t * RESTRICT initial_Z) {
    uECC_word_t z[uECC_WORDS];
    if (initial_Z) {
        vli_set(z, initial_Z);
    } else {
        vli_clear(z);
        z[0] = 1;
    }

    vli_set(X2, X1);
    vli_set(Y2, Y1);

    apply_z(X1, Y1, z);
    EccPoint_double_jacobian(X1, Y1, z);
    apply_z(X2, Y2, z);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
void XYcZ_add(uECC_word_t * RESTRICT X1,
                     uECC_word_t * RESTRICT Y1,
                     uECC_word_t * RESTRICT X2,
                     uECC_word_t * RESTRICT Y2) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_WORDS];

    vli_modSub_fast(t5, X2, X1);  /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);   /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5); /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5); /* t3 = x2*A = C */
    vli_modSub_fast(Y2, Y2, Y1);  /* t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2);   /* t5 = (y2 - y1)^2 = D */

    vli_modSub_fast(t5, t5, X1);  /* t5 = D - B */
    vli_modSub_fast(t5, t5, X2);  /* t5 = D - B - C = x3 */
    vli_modSub_fast(X2, X2, X1);  /* t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2); /* t2 = y1*(C - B) */
    vli_modSub_fast(X2, X1, t5);  /* t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2); /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub_fast(Y2, Y2, Y1);  /* t4 = y3 */

    vli_set(X2, t5);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
void XYcZ_addC(uECC_word_t * RESTRICT X1,
                      uECC_word_t * RESTRICT Y1,
                      uECC_word_t * RESTRICT X2,
                      uECC_word_t * RESTRICT Y2) {
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    uECC_word_t t5[uECC_WORDS];
    uECC_word_t t6[uECC_WORDS];
    uECC_word_t t7[uECC_WORDS];

    vli_modSub_fast(t5, X2, X1);     /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5);    /* t3 = x2*A = C */
    vli_modAdd(t5, Y2, Y1, curve_p); /* t5 = y2 + y1 */
    vli_modSub_fast(Y2, Y2, Y1);     /* t4 = y2 - y1 */

    vli_modSub_fast(t6, X2, X1);     /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6);    /* t2 = y1 * (C - B) = E */
    vli_modAdd(t6, X1, X2, curve_p); /* t6 = B + C */
    vli_modSquare_fast(X2, Y2);      /* t3 = (y2 - y1)^2 = D */
    vli_modSub_fast(X2, X2, t6);     /* t3 = D - (B + C) = x3 */

    vli_modSub_fast(t7, X1, X2);  /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7); /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub_fast(Y2, Y2, Y1);  /* t4 = (y2 - y1)*(B - x3) - E = y3 */

    vli_modSquare_fast(t7, t5);   /* t7 = (y2 + y1)^2 = F */
    vli_modSub_fast(t7, t7, t6);  /* t7 = F - (B + C) = x3' */
    vli_modSub_fast(t6, t7, X1);  /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5); /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub_fast(Y1, t6, Y1);  /* t2 = (y2 + y1)*(x3' - B) - E = y3' */

    vli_set(X1, t7);
}

void EccPoint_mult(EccPoint * RESTRICT result,
                          const EccPoint * RESTRICT point,
                          const uECC_word_t * RESTRICT scalar,
                          const uECC_word_t * RESTRICT initialZ,
                          bitcount_t numBits) {
    /* R0 and R1 */
    uECC_word_t Rx[2][uECC_WORDS];
    uECC_word_t Ry[2][uECC_WORDS];
    uECC_word_t z[uECC_WORDS];
    bitcount_t i;
    uECC_word_t nb;

    vli_set(Rx[1], point->x);
    vli_set(Ry[1], point->y);

    XYcZ_initial_double(Rx[1], Ry[1], Rx[0], Ry[0], initialZ);

    for (i = numBits - 2; i > 0; --i) {
        nb = !vli_testBit(scalar, i);
        XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);
        XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
    }

    nb = !vli_testBit(scalar, 0);
    XYcZ_addC(Rx[1 - nb], Ry[1 - nb], Rx[nb], Ry[nb]);

    /* Find final 1/Z value. */
    vli_modSub_fast(z, Rx[1], Rx[0]);   /* X1 - X0 */
    vli_modMult_fast(z, z, Ry[1 - nb]); /* Yb * (X1 - X0) */
    vli_modMult_fast(z, z, point->x); /* xP * Yb * (X1 - X0) */
    vli_modInv(z, z, curve_p);          /* 1 / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, point->y); /* yP / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, Rx[1 - nb]); /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(Rx[nb], Ry[nb], Rx[1 - nb], Ry[1 - nb]);
    apply_z(Rx[0], Ry[0], z);

    vli_set(result->x, Rx[0]);
    vli_set(result->y, Ry[0]);
}

int EccPoint_compute_public_key(EccPoint *result, uECC_word_t *private) {
    uECC_word_t tmp1[uECC_WORDS];
    uECC_word_t tmp2[uECC_WORDS];
    uECC_word_t *p2[2] = {tmp1, tmp2};
    uECC_word_t carry;

    /* Make sure the private key is in the range [1, n-1]. */
    if (vli_isZero(private)) {
        return 0;
    }

#if (uECC_CURVE == uECC_secp160r1)
    // Don't regularize the bitcount for secp160r1, since it would have a larger performance
    // impact (about 2% slower on average) and requires the vli_xxx_n functions, leading to
    // a significant increase in code size.

    EccPoint_mult(result, &curve_G, private, 0, vli_numBits(private, uECC_WORDS));
#else
    if (vli_cmp(curve_n, private) != 1) {
        return 0;
    }

    // Regularize the bitcount for the private key so that attackers cannot use a side channel
    // attack to learn the number of leading zeros.
    carry = vli_add(tmp1, private, curve_n);
    vli_add(tmp2, tmp1, curve_n);
    EccPoint_mult(result, &curve_G, p2[!carry], 0, (uECC_BYTES * 8) + 1);
#endif

    if (EccPoint_isZero(result)) {
        return 0;
    }
    return 1;
}



#if uECC_CURVE == uECC_secp224r1

/* Routine 3.2.4 RS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf */
void mod_sqrt_secp224r1_rs(uECC_word_t *d1,
                                  uECC_word_t *e1,
                                  uECC_word_t *f1,
                                  const uECC_word_t *d0,
                                  const uECC_word_t *e0,
                                  const uECC_word_t *f0) {
    uECC_word_t t[uECC_WORDS];

    vli_modSquare_fast(t, d0);                 /* t <-- d0 ^ 2 */
    vli_modMult_fast(e1, d0, e0);              /* e1 <-- d0 * e0 */
    vli_modAdd(d1, t, f0, curve_p);            /* d1 <-- t  + f0 */
    vli_modAdd(e1, e1, e1, curve_p);           /* e1 <-- e1 + e1 */
    vli_modMult_fast(f1, t, f0);               /* f1 <-- t  * f0 */
    vli_modAdd(f1, f1, f1, curve_p);           /* f1 <-- f1 + f1 */
    vli_modAdd(f1, f1, f1, curve_p);           /* f1 <-- f1 + f1 */
}

/* Routine 3.2.5 RSS;  from http://www.nsa.gov/ia/_files/nist-routines.pdf */
void mod_sqrt_secp224r1_rss(uECC_word_t *d1,
                                   uECC_word_t *e1,
                                   uECC_word_t *f1,
                                   const uECC_word_t *d0,
                                   const uECC_word_t *e0,
                                   const uECC_word_t *f0,
                                   const bitcount_t j) {
    bitcount_t i;

    vli_set(d1, d0);                           /* d1 <-- d0 */
    vli_set(e1, e0);                           /* e1 <-- e0 */
    vli_set(f1, f0);                           /* f1 <-- f0 */
    for (i = 1; i <= j; i++) {
        mod_sqrt_secp224r1_rs(d1, e1, f1, d1, e1, f1); /* RS (d1,e1,f1,d1,e1,f1) */
    }
}

/* Routine 3.2.6 RM;  from http://www.nsa.gov/ia/_files/nist-routines.pdf */
void mod_sqrt_secp224r1_rm(uECC_word_t *d2,
                                  uECC_word_t *e2,
                                  uECC_word_t *f2,
                                  const uECC_word_t *c,
                                  const uECC_word_t *d0,
                                  const uECC_word_t *e0,
                                  const uECC_word_t *d1,
                                  const uECC_word_t *e1) {
    uECC_word_t t1[uECC_WORDS];
    uECC_word_t t2[uECC_WORDS];

    vli_modMult_fast(t1, e0, e1);              /* t1 <-- e0 * e1 */
    vli_modMult_fast(t1, t1, c);               /* t1 <-- t1 * c */
    vli_modSub_fast(t1, curve_p, t1);          /* t1 <-- p  - t1 */
    vli_modMult_fast(t2, d0, d1);              /* t2 <-- d0 * d1 */
    vli_modAdd(t2, t2, t1, curve_p);           /* t2 <-- t2 + t1 */
    vli_modMult_fast(t1, d0, e1);              /* t1 <-- d0 * e1 */
    vli_modMult_fast(e2, d1, e0);              /* e2 <-- d1 * e0 */
    vli_modAdd(e2, e2, t1, curve_p);           /* e2 <-- e2 + t1 */
    vli_modSquare_fast(f2, e2);                /* f2 <-- e2^2 */
    vli_modMult_fast(f2, f2, c);               /* f2 <-- f2 * c */
    vli_modSub_fast(f2, curve_p, f2);          /* f2 <-- p  - f2 */
    vli_set(d2, t2);                           /* d2 <-- t2 */
}

/* Routine 3.2.7 RP;  from http://www.nsa.gov/ia/_files/nist-routines.pdf */
void mod_sqrt_secp224r1_rp(uECC_word_t *d1,
                                  uECC_word_t *e1,
                                  uECC_word_t *f1,
                                  const uECC_word_t *c,
                                  const uECC_word_t *r) {
    wordcount_t i;
    wordcount_t pow2i = 1;
    uECC_word_t d0[uECC_WORDS];
    uECC_word_t e0[uECC_WORDS] = {1};          /* e0 <-- 1 */
    uECC_word_t f0[uECC_WORDS];

    vli_set(d0, r);                            /* d0 <-- r */
    vli_modSub_fast(f0, curve_p, c);           /* f0 <-- p  - c */
    for (i = 0; i <= 6; i++) {
        mod_sqrt_secp224r1_rss(d1, e1, f1, d0, e0, f0, pow2i); /* RSS (d1,e1,f1,d0,e0,f0,2^i) */
        mod_sqrt_secp224r1_rm(d1, e1, f1, c, d1, e1, d0, e0);  /* RM (d1,e1,f1,c,d1,e1,d0,e0) */
        vli_set(d0, d1);                       /* d0 <-- d1 */
        vli_set(e0, e1);                       /* e0 <-- e1 */
        vli_set(f0, f1);                       /* f0 <-- f1 */
        pow2i *= 2;
    }
}

/* Compute a = sqrt(a) (mod curve_p). */
/* Routine 3.2.8 mp_mod_sqrt_224; from http://www.nsa.gov/ia/_files/nist-routines.pdf */
void mod_sqrt(uECC_word_t *a) {
    bitcount_t i;
    uECC_word_t e1[uECC_WORDS];
    uECC_word_t f1[uECC_WORDS];
    uECC_word_t d0[uECC_WORDS];
    uECC_word_t e0[uECC_WORDS];
    uECC_word_t f0[uECC_WORDS];
    uECC_word_t d1[uECC_WORDS];

    // s = a; using constant instead of random value
    mod_sqrt_secp224r1_rp(d0, e0, f0, a, a);           /* RP (d0, e0, f0, c, s) */
    mod_sqrt_secp224r1_rs(d1, e1, f1, d0, e0, f0);     /* RS (d1, e1, f1, d0, e0, f0) */
    for (i = 1; i <= 95; i++) {
        vli_set(d0, d1);                               /* d0 <-- d1 */
        vli_set(e0, e1);                               /* e0 <-- e1 */
        vli_set(f0, f1);                               /* f0 <-- f1 */
        mod_sqrt_secp224r1_rs(d1, e1, f1, d0, e0, f0); /* RS (d1, e1, f1, d0, e0, f0) */
        if (vli_isZero(d1)) {                          /* if d1 == 0 */
	        break;
        }
    }
    vli_modInv(f1, e0, curve_p);                       /* f1 <-- 1 / e0 */
    vli_modMult_fast(a, d0, f1);                       /* a  <-- d0 / e0 */
}

#else /* uECC_CURVE */

/* Compute a = sqrt(a) (mod curve_p). */
void mod_sqrt(uECC_word_t *a) {
    bitcount_t i;
    uECC_word_t p1[uECC_WORDS] = {1};
    uECC_word_t l_result[uECC_WORDS] = {1};

    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(p1, curve_p, p1); /* p1 = curve_p + 1 */
    for (i = vli_numBits(p1, uECC_WORDS) - 1; i > 1; --i) {
        vli_modSquare_fast(l_result, l_result);
        if (vli_testBit(p1, i)) {
            vli_modMult_fast(l_result, l_result, a);
        }
    }
    vli_set(a, l_result);
}
#endif /* uECC_CURVE */

#if uECC_WORD_SIZE == 1

void vli_nativeToBytes(uint8_t * RESTRICT dest, const uint8_t * RESTRICT src) {
    uint8_t i;
    for (i = 0; i < uECC_BYTES; ++i) {
        dest[i] = src[(uECC_BYTES - 1) - i];
    }
}

#define vli_bytesToNative(dest, src) vli_nativeToBytes((dest), (src))

#elif uECC_WORD_SIZE == 4

void vli_nativeToBytes(uint8_t *bytes, const uint32_t *native) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uint8_t *digit = bytes + 4 * (uECC_WORDS - 1 - i);
        digit[0] = native[i] >> 24;
        digit[1] = native[i] >> 16;
        digit[2] = native[i] >> 8;
        digit[3] = native[i];
    }
}

void vli_bytesToNative(uint32_t *native, const uint8_t *bytes) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        const uint8_t *digit = bytes + 4 * (uECC_WORDS - 1 - i);
        native[i] = ((uint32_t)digit[0] << 24) | ((uint32_t)digit[1] << 16) |
                    ((uint32_t)digit[2] << 8) | (uint32_t)digit[3];
    }
}

#else

void vli_nativeToBytes(uint8_t *bytes, const uint64_t *native) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        uint8_t *digit = bytes + 8 * (uECC_WORDS - 1 - i);
        digit[0] = native[i] >> 56;
        digit[1] = native[i] >> 48;
        digit[2] = native[i] >> 40;
        digit[3] = native[i] >> 32;
        digit[4] = native[i] >> 24;
        digit[5] = native[i] >> 16;
        digit[6] = native[i] >> 8;
        digit[7] = native[i];
    }
}

void vli_bytesToNative(uint64_t *native, const uint8_t *bytes) {
    unsigned i;
    for (i = 0; i < uECC_WORDS; ++i) {
        const uint8_t *digit = bytes + 8 * (uECC_WORDS - 1 - i);
        native[i] = ((uint64_t)digit[0] << 56) | ((uint64_t)digit[1] << 48) |
                    ((uint64_t)digit[2] << 40) | ((uint64_t)digit[3] << 32) |
                    ((uint64_t)digit[4] << 24) | ((uint64_t)digit[5] << 16) |
                    ((uint64_t)digit[6] << 8) | (uint64_t)digit[7];
    }
}

#endif /* uECC_WORD_SIZE */

int uECC_make_key(uint8_t public_key[uECC_BYTES*2], uint8_t private_key[uECC_BYTES]) {
    uECC_word_t private[uECC_WORDS];
    EccPoint public;
    uECC_word_t tries;
    for (tries = 0; tries < MAX_TRIES; ++tries) {
        if (g_rng_function((uint8_t *)private, sizeof(private)) &&
                EccPoint_compute_public_key(&public, private)) {
            vli_nativeToBytes(private_key, private);
            vli_nativeToBytes(public_key, public.x);
            vli_nativeToBytes(public_key + uECC_BYTES, public.y);
            return 1;
        }
    }
    return 0;
}

int uECC_shared_secret(const uint8_t public_key[uECC_BYTES*2],
                       const uint8_t private_key[uECC_BYTES],
                       uint8_t secret[uECC_BYTES]) {
    EccPoint public;
    EccPoint product;
    uECC_word_t private[uECC_WORDS];
    uECC_word_t tmp[uECC_WORDS];
    uECC_word_t *p2[2] = {private, tmp};
    uECC_word_t random[uECC_WORDS];
    uECC_word_t *initial_Z = 0;
    uECC_word_t tries;
    uECC_word_t carry;

    // Try to get a random initial Z value to improve protection against side-channel
    // attacks. If the RNG fails every time (eg it was not defined), we continue so that
    // uECC_shared_secret() can still work without an RNG defined.
    for (tries = 0; tries < MAX_TRIES; ++tries) {
        if (g_rng_function((uint8_t *)random, sizeof(random)) && !vli_isZero(random)) {
            initial_Z = random;
            break;
        }
    }

    vli_bytesToNative(private, private_key);
    vli_bytesToNative(public.x, public_key);
    vli_bytesToNative(public.y, public_key + uECC_BYTES);

#if (uECC_CURVE == uECC_secp160r1)
    // Don't regularize the bitcount for secp160r1.
    EccPoint_mult(&product, &public, private, initial_Z, vli_numBits(private, uECC_WORDS));
#else
    // Regularize the bitcount for the private key so that attackers cannot use a side channel
    // attack to learn the number of leading zeros.
    carry = vli_add(private, private, curve_n);
    vli_add(tmp, private, curve_n);
    EccPoint_mult(&product, &public, p2[!carry], initial_Z, (uECC_BYTES * 8) + 1);
#endif

    vli_nativeToBytes(secret, product.x);
    return !EccPoint_isZero(&product);
}

void uECC_compress(const uint8_t public_key[uECC_BYTES*2], uint8_t compressed[uECC_BYTES+1]) {
    wordcount_t i;
    for (i = 0; i < uECC_BYTES; ++i) {
        compressed[i+1] = public_key[i];
    }
    compressed[0] = 2 + (public_key[uECC_BYTES * 2 - 1] & 0x01);
}

/* Computes result = x^3 + ax + b. result must not overlap x. */
void curve_x_side(uECC_word_t * RESTRICT result, const uECC_word_t * RESTRICT x) {
#if (uECC_CURVE == uECC_secp256k1)
    vli_modSquare_fast(result, x); /* r = x^2 */
    vli_modMult_fast(result, result, x); /* r = x^3 */
    vli_modAdd(result, result, curve_b, curve_p); /* r = x^3 + b */
#else
    uECC_word_t _3[uECC_WORDS] = {3}; /* -a = 3 */

    vli_modSquare_fast(result, x); /* r = x^2 */
    vli_modSub_fast(result, result, _3); /* r = x^2 - 3 */
    vli_modMult_fast(result, result, x); /* r = x^3 - 3x */
    vli_modAdd(result, result, curve_b, curve_p); /* r = x^3 - 3x + b */
#endif
}

void uECC_decompress(const uint8_t compressed[uECC_BYTES+1], uint8_t public_key[uECC_BYTES*2]) {
    EccPoint point;
    vli_bytesToNative(point.x, compressed + 1);
    curve_x_side(point.y, point.x);
    mod_sqrt(point.y);

    if ((point.y[0] & 0x01) != (compressed[0] & 0x01)) {
        vli_sub(point.y, curve_p, point.y);
    }

    vli_nativeToBytes(public_key, point.x);
    vli_nativeToBytes(public_key + uECC_BYTES, point.y);
}

int uECC_valid_public_key(const uint8_t public_key[uECC_BYTES*2]) {
    uECC_word_t tmp1[uECC_WORDS];
    uECC_word_t tmp2[uECC_WORDS];
    EccPoint public;

    vli_bytesToNative(public.x, public_key);
    vli_bytesToNative(public.y, public_key + uECC_BYTES);

    // The point at infinity is invalid.
    if (EccPoint_isZero(&public)) {
        return 0;
    }

    // x and y must be smaller than p.
    if (vli_cmp(curve_p, public.x) != 1 || vli_cmp(curve_p, public.y) != 1) {
        return 0;
    }

    vli_modSquare_fast(tmp1, public.y); /* tmp1 = y^2 */
    curve_x_side(tmp2, public.x); /* tmp2 = x^3 + ax + b */

    /* Make sure that y^2 == x^3 + ax + b */
    return (vli_cmp(tmp1, tmp2) == 0);
}

int uECC_compute_public_key(const uint8_t private_key[uECC_BYTES],
                            uint8_t public_key[uECC_BYTES * 2]) {
    uECC_word_t private[uECC_WORDS];
    EccPoint public;

    vli_bytesToNative(private, private_key);

    if (!EccPoint_compute_public_key(&public, private)) {
        return 0;
    }

    vli_nativeToBytes(public_key, public.x);
    vli_nativeToBytes(public_key + uECC_BYTES, public.y);
    return 1;
}

int uECC_bytes(void) {
    return uECC_BYTES;
}

int uECC_curve(void) {
    return uECC_CURVE;
}

/* -------- ECDSA code -------- */

#if (uECC_CURVE == uECC_secp160r1)
void vli_clear_n(uECC_word_t *vli) {
    vli_clear(vli);
    vli[uECC_N_WORDS - 1] = 0;
}

uECC_word_t vli_isZero_n(const uECC_word_t *vli) {
    if (vli[uECC_N_WORDS - 1]) {
        return 0;
    }
    return vli_isZero(vli);
}

void vli_set_n(uECC_word_t *dest, const uECC_word_t *src) {
    vli_set(dest, src);
    dest[uECC_N_WORDS - 1] = src[uECC_N_WORDS - 1];
}

cmpresult_t vli_cmp_n(const uECC_word_t *left, const uECC_word_t *right) {
    if (left[uECC_N_WORDS - 1] > right[uECC_N_WORDS - 1]) {
        return 1;
    } else if (left[uECC_N_WORDS - 1] < right[uECC_N_WORDS - 1]) {
        return -1;
    }
    return vli_cmp(left, right);
}

void vli_rshift1_n(uECC_word_t *vli) {
    vli_rshift1(vli);
    vli[uECC_N_WORDS - 2] |= vli[uECC_N_WORDS - 1] << (uECC_WORD_BITS - 1);
    vli[uECC_N_WORDS - 1] = vli[uECC_N_WORDS - 1] >> 1;
}

uECC_word_t vli_add_n(uECC_word_t *result,
                             const uECC_word_t *left,
                             const uECC_word_t *right) {
    uECC_word_t carry = vli_add(result, left, right);
    uECC_word_t sum = left[uECC_N_WORDS - 1] + right[uECC_N_WORDS - 1] + carry;
    if (sum != left[uECC_N_WORDS - 1]) {
        carry = (sum < left[uECC_N_WORDS - 1]);
    }
    result[uECC_N_WORDS - 1] = sum;
    return carry;
}

uECC_word_t vli_sub_n(uECC_word_t *result,
                             const uECC_word_t *left,
                             const uECC_word_t *right) {
    uECC_word_t borrow = vli_sub(result, left, right);
    uECC_word_t diff = left[uECC_N_WORDS - 1] - right[uECC_N_WORDS - 1] - borrow;
    if (diff != left[uECC_N_WORDS - 1]) {
        borrow = (diff > left[uECC_N_WORDS - 1]);
    }
    result[uECC_N_WORDS - 1] = diff;
    return borrow;
}

#if !muladd_exists
void muladd(uECC_word_t a,
                   uECC_word_t b,
                   uECC_word_t *r0,
                   uECC_word_t *r1,
                   uECC_word_t *r2) {
    uECC_dword_t p = (uECC_dword_t)a * b;
    uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
    r01 += p;
    *r2 += (r01 < p);
    *r1 = r01 >> uECC_WORD_BITS;
    *r0 = (uECC_word_t)r01;
}
#define muladd_exists 1
#endif

void vli_mult_n(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t r0 = 0;
    uECC_word_t r1 = 0;
    uECC_word_t r2 = 0;
    wordcount_t i, k;

    for (k = 0; k < uECC_N_WORDS * 2 - 1; ++k) {
        wordcount_t min = (k < uECC_N_WORDS ? 0 : (k + 1) - uECC_N_WORDS);
        wordcount_t max = (k < uECC_N_WORDS ? k : uECC_N_WORDS - 1);
        for (i = min; i <= max; ++i) {
            muladd(left[i], right[k - i], &r0, &r1, &r2);
        }
        result[k] = r0;
        r0 = r1;
        r1 = r2;
        r2 = 0;
    }
    result[uECC_N_WORDS * 2 - 1] = r0;
}

void vli_modAdd_n(uECC_word_t *result,
                         const uECC_word_t *left,
                         const uECC_word_t *right,
                         const uECC_word_t *mod) {
    uECC_word_t carry = vli_add_n(result, left, right);
    if (carry || vli_cmp_n(result, mod) >= 0) {
        vli_sub_n(result, result, mod);
    }
}

void vli_modInv_n(uECC_word_t *result, const uECC_word_t *input, const uECC_word_t *mod) {
    uECC_word_t a[uECC_N_WORDS], b[uECC_N_WORDS], u[uECC_N_WORDS], v[uECC_N_WORDS];
    uECC_word_t carry;
    cmpresult_t cmpResult;

    if (vli_isZero_n(input)) {
        vli_clear_n(result);
        return;
    }

    vli_set_n(a, input);
    vli_set_n(b, mod);
    vli_clear_n(u);
    u[0] = 1;
    vli_clear_n(v);
    while ((cmpResult = vli_cmp_n(a, b)) != 0) {
        carry = 0;
        if (EVEN(a)) {
            vli_rshift1_n(a);
            if (!EVEN(u)) {
                carry = vli_add_n(u, u, mod);
            }
            vli_rshift1_n(u);
            if (carry) {
                u[uECC_N_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else if (EVEN(b)) {
            vli_rshift1_n(b);
            if (!EVEN(v)) {
                carry = vli_add_n(v, v, mod);
            }
            vli_rshift1_n(v);
            if (carry) {
                v[uECC_N_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else if (cmpResult > 0) {
            vli_sub_n(a, a, b);
            vli_rshift1_n(a);
            if (vli_cmp_n(u, v) < 0) {
                vli_add_n(u, u, mod);
            }
            vli_sub_n(u, u, v);
            if (!EVEN(u)) {
                carry = vli_add_n(u, u, mod);
            }
            vli_rshift1_n(u);
            if (carry) {
                u[uECC_N_WORDS - 1] |= HIGH_BIT_SET;
            }
        } else {
            vli_sub_n(b, b, a);
            vli_rshift1_n(b);
            if (vli_cmp_n(v, u) < 0) {
                vli_add_n(v, v, mod);
            }
            vli_sub_n(v, v, u);
            if (!EVEN(v)) {
                carry = vli_add_n(v, v, mod);
            }
            vli_rshift1_n(v);
            if (carry) {
                v[uECC_N_WORDS - 1] |= HIGH_BIT_SET;
            }
        }
    }
    vli_set_n(result, u);
}

void vli2_rshift1_n(uECC_word_t *vli) {
    vli_rshift1_n(vli);
    vli[uECC_N_WORDS - 1] |= vli[uECC_N_WORDS] << (uECC_WORD_BITS - 1);
    vli_rshift1_n(vli + uECC_N_WORDS);
}

uECC_word_t vli2_sub_n(uECC_word_t *result,
                              const uECC_word_t *left,
                              const uECC_word_t *right) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_N_WORDS * 2; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}

/* Computes result = (left * right) % curve_n. */
void vli_modMult_n(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    bitcount_t i;
    uECC_word_t product[2 * uECC_N_WORDS];
    uECC_word_t modMultiple[2 * uECC_N_WORDS];
    uECC_word_t tmp[2 * uECC_N_WORDS];
    uECC_word_t *v[2] = {tmp, product};
    uECC_word_t index = 1;

    vli_mult_n(product, left, right);
    vli_clear_n(modMultiple);
    vli_set(modMultiple + uECC_N_WORDS + 1, curve_n);
    vli_rshift1(modMultiple + uECC_N_WORDS + 1);
    modMultiple[2 * uECC_N_WORDS - 1] |= HIGH_BIT_SET;
    modMultiple[uECC_N_WORDS] = HIGH_BIT_SET;

    for (i = 0;
         i <= ((((bitcount_t)uECC_N_WORDS) << uECC_WORD_BITS_SHIFT) + (uECC_WORD_BITS - 1));
         ++i) {
        uECC_word_t borrow = vli2_sub_n(v[1 - index], v[index], modMultiple);
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        vli2_rshift1_n(modMultiple);
    }
    vli_set_n(result, v[index]);
}

#else

#define vli_cmp_n vli_cmp
#define vli_modInv_n vli_modInv
#define vli_modAdd_n vli_modAdd

void vli2_rshift1(uECC_word_t *vli) {
    vli_rshift1(vli);
    vli[uECC_WORDS - 1] |= vli[uECC_WORDS] << (uECC_WORD_BITS - 1);
    vli_rshift1(vli + uECC_WORDS);
}

uECC_word_t vli2_sub(uECC_word_t *result,
                            const uECC_word_t *left,
                            const uECC_word_t *right) {
    uECC_word_t borrow = 0;
    wordcount_t i;
    for (i = 0; i < uECC_WORDS * 2; ++i) {
        uECC_word_t diff = left[i] - right[i] - borrow;
        if (diff != left[i]) {
            borrow = (diff > left[i]);
        }
        result[i] = diff;
    }
    return borrow;
}

/* Computes result = (left * right) % curve_n. */
void vli_modMult_n(uECC_word_t *result, const uECC_word_t *left, const uECC_word_t *right) {
    uECC_word_t product[2 * uECC_WORDS];
    uECC_word_t modMultiple[2 * uECC_WORDS];
    uECC_word_t tmp[2 * uECC_WORDS];
    uECC_word_t *v[2] = {tmp, product};
    bitcount_t i;
    uECC_word_t index = 1;

    vli_mult(product, left, right);
    vli_set(modMultiple + uECC_WORDS, curve_n); /* works if curve_n has its highest bit set */
    vli_clear(modMultiple);

    for (i = 0; i <= uECC_BYTES * 8; ++i) {
        uECC_word_t borrow = vli2_sub(v[1 - index], v[index], modMultiple);
        index = !(index ^ borrow); /* Swap the index if there was no borrow */
        vli2_rshift1(modMultiple);
    }
    vli_set(result, v[index]);
}
#endif /* (uECC_CURVE != uECC_secp160r1) */

int uECC_sign_with_k(const uint8_t private_key[uECC_BYTES],
                            const uint8_t message_hash[uECC_BYTES],
                            uECC_word_t k[uECC_N_WORDS],
                            uint8_t signature[uECC_BYTES*2]) {
    uECC_word_t tmp[uECC_N_WORDS];
    uECC_word_t s[uECC_N_WORDS];
    uECC_word_t *k2[2] = {tmp, s};
    EccPoint p;
    uECC_word_t carry;
    uECC_word_t tries;

    /* Make sure 0 < k < curve_n */
    if (vli_isZero(k) || vli_cmp_n(curve_n, k) != 1) {
        return 0;
    }

#if (uECC_CURVE == uECC_secp160r1)
    /* Make sure that we don't leak timing information about k.
       See http://eprint.iacr.org/2011/232.pdf */
    vli_add_n(tmp, k, curve_n);
    carry = (tmp[uECC_WORDS] & 0x02);
    vli_add_n(s, tmp, curve_n);

    /* p = k * G */
    EccPoint_mult(&p, &curve_G, k2[!carry], 0, (uECC_BYTES * 8) + 2);
#else
    /* Make sure that we don't leak timing information about k.
       See http://eprint.iacr.org/2011/232.pdf */
    carry = vli_add(tmp, k, curve_n);
    vli_add(s, tmp, curve_n);

    /* p = k * G */
    EccPoint_mult(&p, &curve_G, k2[!carry], 0, (uECC_BYTES * 8) + 1);

    /* r = x1 (mod n) */
    if (vli_cmp(curve_n, p.x) != 1) {
        vli_sub(p.x, p.x, curve_n);
    }
#endif
    if (vli_isZero(p.x)) {
        return 0;
    }

    // Attempt to get a random number to prevent side channel analysis of k.
    // If the RNG fails every time (eg it was not defined), we continue so that
    // deterministic signing can still work (with reduced security) without
    // an RNG defined.
    carry = 0; // use to signal that the RNG succeeded at least once.
    for (tries = 0; tries < MAX_TRIES; ++tries) {
        if (!g_rng_function((uint8_t *)tmp, sizeof(tmp))) {
            continue;
        }
        carry = 1;
        if (!vli_isZero(tmp)) {
            break;
        }
    }
    if (!carry) {
        vli_clear(tmp);
        tmp[0] = 1;
    }

    /* Prevent side channel analysis of vli_modInv() to determine
       bits of k / the private key by premultiplying by a random number */
    vli_modMult_n(k, k, tmp); /* k' = rand * k */
    vli_modInv_n(k, k, curve_n); /* k = 1 / k' */
    vli_modMult_n(k, k, tmp); /* k = 1 / k */

    vli_nativeToBytes(signature, p.x); /* store r */

    tmp[uECC_N_WORDS - 1] = 0;
    vli_bytesToNative(tmp, private_key); /* tmp = d */
    s[uECC_N_WORDS - 1] = 0;
    vli_set(s, p.x);
    vli_modMult_n(s, tmp, s); /* s = r*d */

    vli_bytesToNative(tmp, message_hash);
    vli_modAdd_n(s, tmp, s, curve_n); /* s = e + r*d */
    vli_modMult_n(s, s, k); /* s = (e + r*d) / k */
#if (uECC_CURVE == uECC_secp160r1)
    if (s[uECC_N_WORDS - 1]) {
        return 0;
    }
#endif
    vli_nativeToBytes(signature + uECC_BYTES, s);
    return 1;
}

int uECC_sign(const uint8_t private_key[uECC_BYTES],
              const uint8_t message_hash[uECC_BYTES],
              uint8_t signature[uECC_BYTES*2]) {
    uECC_word_t k[uECC_N_WORDS];
    uECC_word_t tries;

    for (tries = 0; tries < MAX_TRIES; ++tries) {
        if(g_rng_function((uint8_t *)k, sizeof(k))) {
        #if (uECC_CURVE == uECC_secp160r1)
            k[uECC_WORDS] &= 0x01;
        #endif
            if (uECC_sign_with_k(private_key, message_hash, k, signature)) {
                return 1;
            }
        }
    }
    return 0;
}

/* Compute an HMAC using K as a key (as in RFC 6979). Note that K is always
   the same size as the hash result size. */
void HMAC_init(uECC_HashContext *hash_context, const uint8_t *K) {
    uint8_t *pad = hash_context->tmp + 2 * hash_context->result_size;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i)
        pad[i] = K[i] ^ 0x36;
    for (; i < hash_context->block_size; ++i)
        pad[i] = 0x36;

    hash_context->init_hash(hash_context);
    hash_context->update_hash(hash_context, pad, hash_context->block_size);
}

void HMAC_update(uECC_HashContext *hash_context,
                        const uint8_t *message,
                        unsigned message_size) {
    hash_context->update_hash(hash_context, message, message_size);
}

void HMAC_finish(uECC_HashContext *hash_context, const uint8_t *K, uint8_t *result) {
    uint8_t *pad = hash_context->tmp + 2 * hash_context->result_size;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i)
        pad[i] = K[i] ^ 0x5c;
    for (; i < hash_context->block_size; ++i)
        pad[i] = 0x5c;

    hash_context->finish_hash(hash_context, result);

    hash_context->init_hash(hash_context);
    hash_context->update_hash(hash_context, pad, hash_context->block_size);
    hash_context->update_hash(hash_context, result, hash_context->result_size);
    hash_context->finish_hash(hash_context, result);
}

/* V = HMAC_K(V) */
void update_V(uECC_HashContext *hash_context, uint8_t *K, uint8_t *V) {
    HMAC_init(hash_context, K);
    HMAC_update(hash_context, V, hash_context->result_size);
    HMAC_finish(hash_context, K, V);
}

/* Deterministic signing, similar to RFC 6979. Differences are:
    * We just use (truncated) H(m) directly rather than bits2octets(H(m))
      (it is not reduced modulo curve_n).
    * We generate a value for k (aka T) directly rather than converting endianness.

   Layout of hash_context->tmp: <K> | <V> | (1 byte overlapped 0x00 or 0x01) / <HMAC pad> */
int uECC_sign_deterministic(const uint8_t private_key[uECC_BYTES],
                            const uint8_t message_hash[uECC_BYTES],
                            uECC_HashContext *hash_context,
                            uint8_t signature[uECC_BYTES*2]) {
    uint8_t *K = hash_context->tmp;
    uint8_t *V = K + hash_context->result_size;
    uECC_word_t tries;
    unsigned i;
    for (i = 0; i < hash_context->result_size; ++i) {
        V[i] = 0x01;
        K[i] = 0;
    }

    // K = HMAC_K(V || 0x00 || int2octets(x) || h(m))
    HMAC_init(hash_context, K);
    V[hash_context->result_size] = 0x00;
    HMAC_update(hash_context, V, hash_context->result_size + 1);
    HMAC_update(hash_context, private_key, uECC_BYTES);
    HMAC_update(hash_context, message_hash, uECC_BYTES);
    HMAC_finish(hash_context, K, K);

    update_V(hash_context, K, V);

    // K = HMAC_K(V || 0x01 || int2octets(x) || h(m))
    HMAC_init(hash_context, K);
    V[hash_context->result_size] = 0x01;
    HMAC_update(hash_context, V, hash_context->result_size + 1);
    HMAC_update(hash_context, private_key, uECC_BYTES);
    HMAC_update(hash_context, message_hash, uECC_BYTES);
    HMAC_finish(hash_context, K, K);

    update_V(hash_context, K, V);

    for (tries = 0; tries < MAX_TRIES; ++tries) {
        uECC_word_t T[uECC_N_WORDS];
        uint8_t *T_ptr = (uint8_t *)T;
        unsigned T_bytes = 0;
        while (T_bytes < sizeof(T)) {
            update_V(hash_context, K, V);
            for (i = 0; i < hash_context->result_size && T_bytes < sizeof(T); ++i, ++T_bytes) {
                T_ptr[T_bytes] = V[i];
            }
        }
    #if (uECC_CURVE == uECC_secp160r1)
        T[uECC_WORDS] &= 0x01;
    #endif

        if (uECC_sign_with_k(private_key, message_hash, T, signature)) {
            return 1;
        }

        // K = HMAC_K(V || 0x00)
        HMAC_init(hash_context, K);
        V[hash_context->result_size] = 0x00;
        HMAC_update(hash_context, V, hash_context->result_size + 1);
        HMAC_finish(hash_context, K, K);

        update_V(hash_context, K, V);
    }
    return 0;
}

bitcount_t smax(bitcount_t a, bitcount_t b) {
    return (a > b ? a : b);
}

int uECC_verify(const uint8_t public_key[uECC_BYTES*2],
                const uint8_t hash[uECC_BYTES],
                const uint8_t signature[uECC_BYTES*2]) {
    uECC_word_t u1[uECC_N_WORDS], u2[uECC_N_WORDS];
    uECC_word_t z[uECC_N_WORDS];
    EccPoint public, sum;
    uECC_word_t rx[uECC_WORDS];
    uECC_word_t ry[uECC_WORDS];
    uECC_word_t tx[uECC_WORDS];
    uECC_word_t ty[uECC_WORDS];
    uECC_word_t tz[uECC_WORDS];
    const EccPoint *points[4];
    const EccPoint *point;
    bitcount_t numBits;
    bitcount_t i;
    uECC_word_t r[uECC_N_WORDS], s[uECC_N_WORDS];
    r[uECC_N_WORDS - 1] = 0;
    s[uECC_N_WORDS - 1] = 0;

    vli_bytesToNative(public.x, public_key);
    vli_bytesToNative(public.y, public_key + uECC_BYTES);
    vli_bytesToNative(r, signature);
    vli_bytesToNative(s, signature + uECC_BYTES);

    if (vli_isZero(r) || vli_isZero(s)) { /* r, s must not be 0. */
        return 0;
    }

#if (uECC_CURVE != uECC_secp160r1)
    if (vli_cmp(curve_n, r) != 1 || vli_cmp(curve_n, s) != 1) { /* r, s must be < n. */
        return 0;
    }
#endif

    /* Calculate u1 and u2. */
    vli_modInv_n(z, s, curve_n); /* Z = s^-1 */
    u1[uECC_N_WORDS - 1] = 0;
    vli_bytesToNative(u1, hash);
    vli_modMult_n(u1, u1, z); /* u1 = e/s */
    vli_modMult_n(u2, r, z); /* u2 = r/s */

    /* Calculate sum = G + Q. */
    vli_set(sum.x, public.x);
    vli_set(sum.y, public.y);
    vli_set(tx, curve_G.x);
    vli_set(ty, curve_G.y);
    vli_modSub_fast(z, sum.x, tx); /* Z = x2 - x1 */
    XYcZ_add(tx, ty, sum.x, sum.y);
    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(sum.x, sum.y, z);

    /* Use Shamir's trick to calculate u1*G + u2*Q */
    points[0] = 0;
    points[1] = &curve_G;
    points[2] = &public;
    points[3] = &sum;
    numBits = smax(vli_numBits(u1, uECC_N_WORDS), vli_numBits(u2, uECC_N_WORDS));

    point = points[(!!vli_testBit(u1, numBits - 1)) | ((!!vli_testBit(u2, numBits - 1)) << 1)];
    vli_set(rx, point->x);
    vli_set(ry, point->y);
    vli_clear(z);
    z[0] = 1;

    for (i = numBits - 2; i >= 0; --i) {
        uECC_word_t index;
        EccPoint_double_jacobian(rx, ry, z);

        index = (!!vli_testBit(u1, i)) | ((!!vli_testBit(u2, i)) << 1);
        point = points[index];
        if (point) {
            vli_set(tx, point->x);
            vli_set(ty, point->y);
            apply_z(tx, ty, z);
            vli_modSub_fast(tz, rx, tx); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry);
            vli_modMult_fast(z, z, tz);
        }
    }

    vli_modInv(z, z, curve_p); /* Z = 1/Z */
    apply_z(rx, ry, z);

    /* v = x1 (mod n) */
#if (uECC_CURVE != uECC_secp160r1)
    if (vli_cmp(curve_n, rx) != 1) {
        vli_sub(rx, rx, curve_n);
    }
#endif

    /* Accept only if v == r. */
    return vli_equal(rx, r);
}



//P=P+Q P(X1,Y1),Q(X2,Y2)
void EccPoint_add(uECC_word_t * RESTRICT X1,
                  uECC_word_t * RESTRICT Y1,
                  uECC_word_t * RESTRICT X2,
                  uECC_word_t * RESTRICT Y2){
    uECC_word_t one[uECC_WORDS];
    
    // t1 = X1, t2 = X2, t4 = y1, t5 = y2
    
    
    uECC_word_t A[uECC_WORDS];
    uECC_word_t B[uECC_WORDS];
    
    uECC_word_t X3[uECC_WORDS];
    uECC_word_t Y3[uECC_WORDS];
    
    
    
    vli_clear(one);
    one[0] = 1;
   
    if(vli_equal(X1, X2)&&vli_equal(Y1, Y2)){
        EccPoint_double_jacobian(X1, Y1, one);
        vli_modInv(one, one, curve_p);
        apply_z(X1, Y1, one);
        return;
    }else if(vli_equal(X1, X2)){
        vli_clear(X1);
        vli_clear(Y1);
        return;
    }else{
        /*vli_modSub(t3, X1, X2, curve_p); // t3 = t1-t2
        vli_modSub(t6, Y1, Y2, curve_p); // t6 = t4-t5
        vli_modAdd(t7, X1, X2, curve_p); // t7 = t1+t2
        vli_modAdd(t8, Y1, Y2, curve_p); // t8 = t4+t5
        vli_modMult_fast(t9, t3, t3);  // t9 = t3*2
        vli_modMult_fast(t9, t9, t7); // t9 = t7*t3^2
        vli_modMult_fast(X1, t6, t6); // X3 = t6^2
        vli_modSub(X1, X1, t9, curve_p); // X3 = t6^2 - t9
        
        vli_modMult_fast(t7, t9, t9); // t7 = t9^2
        vli_modSub(t7, t7, X1, curve_p); // t7 = t9^2-X3
        vli_modSub(t7, t7, X1, curve_p); // t7 = t9^2-2*X3 = t10
        vli_modMult_fast(t7, t7, t6); // t7 = t10*t6
        vli_modMult_fast(t9, t3, t3); // t9 = t3^2
        vli_modMult_fast(t9, t9, t3); // t9 = t3^3
        vli_modMult_fast(t9, t9, t8); // t9 = t8*t3^3
        vli_modSub(Y1, t7, t9 , curve_p); // Y3 =t10*t6 - t8*t3^3
        vli_modMult_fast(X1, X1, four);
        vli_modMult_fast(Y1, Y1, four);
        vli_modMult_fast(t3, t3, two);
        vli_modInv(t3, t3, curve_p);
        apply_z(X1, Y1, t3);*/
        
        vli_modSub(A, Y1, Y2, curve_p);
        vli_modSub(B, X1, X2, curve_p);
        vli_modInv(B, B, curve_p);
        vli_modMult_fast(A, B, A);
        
        vli_modMult_fast(X3, A, A);
        vli_modSub(X3, X3, X1, curve_p);
        vli_modSub(X3, X3, X2, curve_p);
        
        vli_modSub(B, X1, X3, curve_p);
        vli_modMult_fast(B, B, A);
        vli_modSub(Y3, B, Y1, curve_p);
        
        vli_set(X1, X3);
        vli_set(Y1, Y3);
        return;
    }
    
}


void testECC(){
    EccPoint t1;
    EccPoint t2;
    EccPoint t3;
    
    uECC_word_t one[uECC_N_WORDS];
    uECC_word_t two[uECC_N_WORDS];
    uECC_word_t three[uECC_N_WORDS];
    
   
    vli_clear(one);
    vli_clear(two);
    vli_clear(three);
    
    one[0] = 1;
    two[0] = 2;
    three[0] = 3;
    
    //vli_modAdd(two, one, one, curve_p);
    
    EccPoint_mult(&t1, &curve_G, three, 0, vli_numBits(three, uECC_WORDS));
    
    vli_set(t2.x, curve_G.x);
    vli_set(t2.y, curve_G.y);
    vli_set(t3.x, curve_G.x);
    vli_set(t3.y, curve_G.y);
    
    EccPoint_mult(&t3, &curve_G, two, 0, vli_numBits(two, uECC_WORDS));
    
    EccPoint_add(t2.x, t2.y, t3.x, t3.y);
    //EccPoint_add(t2.x, t2.y, t3.x, t3.y);
    
    
    printf("%lld\n",t1.y[0]);
    printf("%lld\n",t2.y[0]);
    
    curve_x_side(one,t2.x);
    vli_modSquare_fast(two,t2.y);
    
    if(vli_equal(one, two)){
        printf("equal on curve \n");
    }
    
    if(vli_equal(t1.x, t2.x)&vli_equal(t1.y,t2.y)){
        printf("equal \n");
    }else{
        printf("error \n");
    }
    
}