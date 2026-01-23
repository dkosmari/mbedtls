/*
 *  Threading abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Ensure gmtime_r is available even with -std=c99; must be defined before
 * mbedtls_config.h, which pulls in glibc's features.h. Harmless on other platforms.
 */
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "common.h"

#if defined(MBEDTLS_THREADING_C)

#include "threading_internal.h"

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif /* !_WIN32 && (unix || __unix || __unix__ ||
        * (__APPLE__ && __MACH__)) */

#if !((defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L) ||     \
    (defined(_POSIX_THREAD_SAFE_FUNCTIONS) &&                     \
    _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L))
/*
 * This is a convenience shorthand macro to avoid checking the long
 * preprocessor conditions above. Ideally, we could expose this macro in
 * platform_util.h and simply use it in platform_util.c, threading.c and
 * threading.h. However, this macro is not part of the Mbed TLS public API, so
 * we keep it private by only defining it in this file
 */

#if !(defined(_WIN32) && !defined(EFIX64) && !defined(EFI32))
#define THREADING_USE_GMTIME
#endif /* ! ( defined(_WIN32) && !defined(EFIX64) && !defined(EFI32) ) */

#endif /* !( ( defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L ) || \
             ( defined(_POSIX_THREAD_SAFE_FUNCTIONS ) && \
                _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L ) ) */

#endif /* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

#ifdef __WIIU__
#undef THREADING_USE_GMTIME
#endif

#if defined(MBEDTLS_THREADING_PTHREAD)
static void threading_mutex_init_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    /* One problem here is that calling lock on a pthread mutex without first
     * having initialised it is undefined behaviour. Obviously we cannot check
     * this here in a thread safe manner without a significant performance
     * hit, so state transitions are checked in tests only via the state
     * variable. Please make sure any new mutex that gets added is exercised in
     * tests; see framework/tests/src/threading_helpers.c for more details. */
    (void) pthread_mutex_init(&mutex->mutex, NULL);
}

static void threading_mutex_free_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    (void) pthread_mutex_destroy(&mutex->mutex);
}

static int threading_mutex_lock_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    if (pthread_mutex_lock(&mutex->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return 0;
}

static int threading_mutex_unlock_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    if (pthread_mutex_unlock(&mutex->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return 0;
}

void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_init_pthread;
void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_free_pthread;
int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_lock_pthread;
int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_unlock_pthread;

/*
 * With pthreads we can statically initialize mutexes
 */
#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER, 1 }

#elif defined(MBEDTLS_THREADING_WIIU)
#include <coreinit/atomic.h>
#include <coreinit/thread.h>
#include <coreinit/time.h>

enum wiiu_mutex_state {
    WIIU_MUTEX_NOT_INIT     = 0,
    WIIU_MUTEX_INITIALIZING = 1,
    WIIU_MUTEX_INITIALIZED  = 2
};

static void threading_mutex_init_wiiu(mbedtls_threading_mutex_t *mutex)
{
    if (!mutex)
        return;

    OSInitMutex(&mutex->mutex);
    if (mutex->state == WIIU_MUTEX_INITIALIZING)
        while (!OSCompareAndSwapAtomic(&mutex->state,
                                       WIIU_MUTEX_INITIALIZING,
                                       WIIU_MUTEX_INITIALIZED))
            ;
}

static void threading_mutex_free_wiiu(mbedtls_threading_mutex_t *mutex)
{
    if (mutex)
        memset(mutex, 0, sizeof *mutex);
}

static int threading_mutex_lock_wiiu(mbedtls_threading_mutex_t *mutex)
{
    if (!mutex)
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    while (mutex->state != WIIU_MUTEX_INITIALIZED) {
        /* Exactly one thread must initialize this mutex. */
        if (OSCompareAndSwapAtomic(&mutex->state,
                                   WIIU_MUTEX_NOT_INIT,
                                   WIIU_MUTEX_INITIALIZING)) {
            threading_mutex_init_wiiu(mutex);
            break;
        } else {
            /* Make other threads sleep a bit. */
            OSSleepTicks(OSMicrosecondsToTicks(100));
        }
    }

    OSLockMutex(&mutex->mutex);
    return 0;
}

static int threading_mutex_unlock_wiiu(mbedtls_threading_mutex_t *mutex)
{
    if (!mutex)
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;

    OSUnlockMutex(&mutex->mutex);
    return 0;
}

void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_init_wiiu;
void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_free_wiiu;
int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_lock_wiiu;
int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_unlock_wiiu;

#endif /* MBEDTLS_THREADING_PTHREAD, MBEDTLS_THREADING_WIIU */

#if defined(MBEDTLS_THREADING_ALT)
static int threading_mutex_fail(mbedtls_threading_mutex_t *mutex)
{
    ((void) mutex);
    return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
}
static void threading_mutex_dummy(mbedtls_threading_mutex_t *mutex)
{
    ((void) mutex);
    return;
}

void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_dummy;
void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_dummy;
int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_fail;
int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_fail;

/*
 * Set functions pointers and initialize global mutexes
 */
void mbedtls_threading_set_alt(void (*mutex_init)(mbedtls_threading_mutex_t *),
                               void (*mutex_free)(mbedtls_threading_mutex_t *),
                               int (*mutex_lock)(mbedtls_threading_mutex_t *),
                               int (*mutex_unlock)(mbedtls_threading_mutex_t *))
{
    mbedtls_mutex_init = mutex_init;
    mbedtls_mutex_free = mutex_free;
    mbedtls_mutex_lock = mutex_lock;
    mbedtls_mutex_unlock = mutex_unlock;

#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_init(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_init(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_init(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_rngdata_mutex);
#endif
}

/*
 * Free global mutexes
 */
void mbedtls_threading_free_alt(void)
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_free(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_free(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_free(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_rngdata_mutex);
#endif
}
#endif /* MBEDTLS_THREADING_ALT */

/*
 * Define global mutexes
 */
#ifndef MUTEX_INIT
#define MUTEX_INIT
#endif
#if defined(MBEDTLS_FS_IO)
mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex MUTEX_INIT;
#endif
#if defined(THREADING_USE_GMTIME)
mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex MUTEX_INIT;
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex MUTEX_INIT;
mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex MUTEX_INIT;
mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex MUTEX_INIT;
#endif

#endif /* MBEDTLS_THREADING_C */
