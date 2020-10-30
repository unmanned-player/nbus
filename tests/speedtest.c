/* SPDX-License-Identifier: Apache-2.0 */

#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>

#include "speedtest.h"

#include "nbus/nbus.h"

pthread_mutex_t lock;
pthread_cond_t  cond;

/* Is server ready? */
volatile bool is_ready = false;
volatile bool is_running = true;

volatile uint64_t cln_times = 0, cln_counts = 0;

static void sig__breaker(int signo)
{
    (void)signo;

    pthread_mutex_lock(&lock);
    is_running = false;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
}

int main(void)
{
    pthread_t threads[MAX_THREADS];
    size_t i;

    signal(SIGINT,  sig__breaker);
    signal(SIGTERM, sig__breaker);
    signal(SIGHUP,  sig__breaker);

    pthread_mutex_init(&lock, NULL);
    pthread_cond_init(&cond, NULL);

    pthread_create(&threads[0], NULL, main_server, NULL);
    for (i = 1; i < MAX_THREADS; i++) {
        pthread_create(&threads[i], NULL, main_client, NULL);
    }

    for (i = 1; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_join(threads[0], NULL);

    pthread_mutex_destroy(&lock);
    pthread_cond_destroy(&cond);

    printf("client = %" PRIu64 ", %" PRIu64 ", %lf\n",
            cln_counts, cln_times,
            ((double)cln_counts / ((double)cln_times / (double)1000000)));
}
