/* SPDX-License-Identifier: Apache-2.0 */

#ifndef NBUS__SPEED_TEST_H
#define NBUS__SPEED_TEST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <time.h>

#include "internal.h"

#include <pthread.h>

/**
 * 0 - server, 1..N - clients.
**/
#define MAX_THREADS                     8

/**
 * Maximum RPCs each client will invoke.
**/
#define MAX_MESSAGES                    1000

#ifdef __cplusplus
extern "C" {
#endif

extern pthread_mutex_t lock;
extern pthread_cond_t  cond;

/* Is server ready? */
extern volatile bool is_ready, is_running;

extern volatile uint64_t cln_times, cln_counts;

/**
 * Get monotonic time-stamp in microseconds.
**/
F_INLINE uint64_t clock_get_ts(void)
{
    struct timespec tv = { .tv_sec = 0, .tv_nsec = 0 };

    if (clock_gettime(CLOCK_MONOTONIC, &tv) == 0) {
        return ((uint64_t)tv.tv_sec * (uint64_t)1000000UL) + ((uint64_t)tv.tv_nsec / (uint64_t)1000);
    }
    return 0;
}

F_INLINE void msg_count_time(uint64_t ts_diff)
{
    pthread_mutex_lock(&lock);
    cln_counts++;
    cln_times += ts_diff;
    pthread_mutex_unlock(&lock);
}

/**
 * Called inside server to notify everyone that the server is ready.
**/
F_INLINE void set_server_ready(void)
{
    pthread_mutex_lock(&lock);
    is_ready = true;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
}

/**
 * Called inside client threads to wait for the server to become ready.
**/
F_INLINE void wait_server_ready(void)
{
    pthread_mutex_lock(&lock);
    while(is_ready == false && is_running == true) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
}

/**
 * Per-client thread.
**/
void *main_client(void *);

/**
 * Server thread.
**/
void *main_server(void *);

#ifdef __cplusplus
}
#endif

#endif /* NBUS__SPEED_TEST_H */
