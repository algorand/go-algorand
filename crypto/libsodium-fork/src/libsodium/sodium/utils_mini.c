#ifndef __STDC_WANT_LIB_EXT1__
# define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif

#ifdef _WIN32
# include <windows.h>
# include <wincrypt.h>
#else
# include <unistd.h>
#endif

#ifndef HAVE_C_VARARRAYS
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# elif !defined(alloca)
#  if defined(__clang__) || defined(__GNUC__)
#   define alloca __builtin_alloca
#  elif defined _AIX
#   define alloca __alloca
#  elif defined _MSC_VER
#   include <malloc.h>
#   define alloca _alloca
#  else
#   include <stddef.h>
#   ifdef  __cplusplus
extern "C"
#   endif
void *alloca (size_t);
#  endif
# endif
#endif

#include "core.h"
#include "randombytes.h"
#include "utils.h"

#ifndef ENOSYS
# define ENOSYS ENXIO
#endif

#if defined(_WIN32) && \
    (!defined(WINAPI_FAMILY) || WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
# define WINAPI_DESKTOP
#endif

#define CANARY_SIZE 16U
#define GARBAGE_VALUE 0xdb

#ifndef MAP_NOCORE
# define MAP_NOCORE 0
#endif
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
# define MAP_ANON MAP_ANONYMOUS
#endif
#if defined(WINAPI_DESKTOP) || (defined(MAP_ANON) && defined(HAVE_MMAP)) || \
    defined(HAVE_POSIX_MEMALIGN)
# define HAVE_ALIGNED_MALLOC
#endif
#if defined(HAVE_MPROTECT) && \
    !(defined(PROT_NONE) && defined(PROT_READ) && defined(PROT_WRITE))
# undef HAVE_MPROTECT
#endif
#if defined(HAVE_ALIGNED_MALLOC) && \
    (defined(WINAPI_DESKTOP) || defined(HAVE_MPROTECT))
# define HAVE_PAGE_PROTECTION
#endif
#if !defined(MADV_DODUMP) && defined(MADV_CORE)
# define MADV_DODUMP   MADV_CORE
# define MADV_DONTDUMP MADV_NOCORE
#endif

static size_t        page_size;
static unsigned char canary[CANARY_SIZE];

/* LCOV_EXCL_START */
#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_memzero_lto(void *const  pnt,
                                            const size_t len);
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_memzero_lto(void *const  pnt,
                                            const size_t len)
{
    (void) pnt; /* LCOV_EXCL_LINE */
    (void) len; /* LCOV_EXCL_LINE */
}
#endif
/* LCOV_EXCL_STOP */

void
sodium_memzero(void *const pnt, const size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(pnt, len);
#elif defined(HAVE_MEMSET_S)
    if (len > 0U && memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(pnt, len);
#elif defined(HAVE_EXPLICIT_MEMSET)
    explicit_memset(pnt, 0, len);
#elif HAVE_WEAK_SYMBOLS
    memset(pnt, 0, len);
    _sodium_dummy_symbol_to_prevent_memzero_lto(pnt, len);
# ifdef HAVE_INLINE_ASM
    __asm__ __volatile__ ("" : : "r"(pnt) : "memory");
# endif
#else
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}


#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_memcmp_lto(const unsigned char *b1,
                                           const unsigned char *b2,
                                           const size_t         len);
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_memcmp_lto(const unsigned char *b1,
                                           const unsigned char *b2,
                                           const size_t         len)
{
    (void) b1;
    (void) b2;
    (void) len;
}
#endif

int
sodium_memcmp(const void *const b1_, const void *const b2_, size_t len)
{
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
#else
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
#endif
    size_t                 i;
    volatile unsigned char d = 0U;

#if HAVE_WEAK_SYMBOLS
    _sodium_dummy_symbol_to_prevent_memcmp_lto(b1, b2, len);
#endif
    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1,
                                            const unsigned char *b2,
                                            const size_t         len);
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1,
                                            const unsigned char *b2,
                                            const size_t         len)
{
    (void) b1;
    (void) b2;
    (void) len;
}
#endif

int
sodium_compare(const unsigned char *b1_, const unsigned char *b2_, size_t len)
{
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = b1_;
    const unsigned char *b2 = b2_;
#else
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
#endif
    size_t                 i;
    volatile unsigned char gt = 0U;
    volatile unsigned char eq = 1U;
    uint16_t               x1, x2;

#if HAVE_WEAK_SYMBOLS
    _sodium_dummy_symbol_to_prevent_compare_lto(b1, b2, len);
#endif
    i = len;
    while (i != 0U) {
        i--;
        x1 = b1[i];
        x2 = b2[i];
        gt |= ((x2 - x1) >> 8) & eq;
        eq &= ((x2 ^ x1) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}

int
sodium_is_zero(const unsigned char *n, const size_t nlen)
{
    size_t                 i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}


void
sodium_add(unsigned char *a, const unsigned char *b, const size_t len)
{
    size_t        i;
    uint_fast16_t c = 0U;

#ifdef HAVE_AMD64_ASM
    uint64_t t64, t64_2, t64_3;
    uint32_t t32;

    if (len == 12U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "movl 8(%[in]), %[t32] \n"
            "addq %[t64], (%[out]) \n"
            "adcl %[t32], 8(%[out]) \n"
            : [t64] "=&r"(t64), [t32] "=&r"(t32)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    } else if (len == 24U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "movq 8(%[in]), %[t64_2] \n"
            "movq 16(%[in]), %[t64_3] \n"
            "addq %[t64], (%[out]) \n"
            "adcq %[t64_2], 8(%[out]) \n"
            "adcq %[t64_3], 16(%[out]) \n"
            : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2), [t64_3] "=&r"(t64_3)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    } else if (len == 8U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "addq %[t64], (%[out]) \n"
            : [t64] "=&r"(t64)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    }
#endif
    for (i = 0U; i < len; i++) {
        c += (uint_fast16_t) a[i] + (uint_fast16_t) b[i];
        a[i] = (unsigned char) c;
        c >>= 8;
    }
}

void
sodium_sub(unsigned char *a, const unsigned char *b, const size_t len)
{
    uint_fast16_t c = 0U;
    size_t        i;

#ifdef HAVE_AMD64_ASM
    uint64_t t64_1, t64_2, t64_3, t64_4;
    uint64_t t64_5, t64_6, t64_7, t64_8;
    uint32_t t32;

    if (len == 64U) {
        __asm__ __volatile__(
            "movq   (%[in]), %[t64_1] \n"
            "movq  8(%[in]), %[t64_2] \n"
            "movq 16(%[in]), %[t64_3] \n"
            "movq 24(%[in]), %[t64_4] \n"
            "movq 32(%[in]), %[t64_5] \n"
            "movq 40(%[in]), %[t64_6] \n"
            "movq 48(%[in]), %[t64_7] \n"
            "movq 56(%[in]), %[t64_8] \n"
            "subq %[t64_1],   (%[out]) \n"
            "sbbq %[t64_2],  8(%[out]) \n"
            "sbbq %[t64_3], 16(%[out]) \n"
            "sbbq %[t64_4], 24(%[out]) \n"
            "sbbq %[t64_5], 32(%[out]) \n"
            "sbbq %[t64_6], 40(%[out]) \n"
            "sbbq %[t64_7], 48(%[out]) \n"
            "sbbq %[t64_8], 56(%[out]) \n"
            : [t64_1] "=&r"(t64_1), [t64_2] "=&r"(t64_2), [t64_3] "=&r"(t64_3), [t64_4] "=&r"(t64_4),
              [t64_5] "=&r"(t64_5), [t64_6] "=&r"(t64_6), [t64_7] "=&r"(t64_7), [t64_8] "=&r"(t64_8)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    }
#endif
    for (i = 0U; i < len; i++) {
        c = (uint_fast16_t) a[i] - (uint_fast16_t) b[i] - c;
        a[i] = (unsigned char) c;
        c = (c >> 8) & 1U;
    }
}
