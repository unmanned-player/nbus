/* SPDX-License-Identifier: Apache-2.0 */

#include "speedtest.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <poll.h>
#include <unistd.h>

static int do_echo(nbus_context_t *ctx, uint8_t proto, const char *peer, const char *name, const void *data, const size_t n)
{
    char buf[256];
    size_t len;

    (void)proto;
    (void)peer;
    (void)name;

    len = snprintf(buf, sizeof(buf), "%.*s", (int)n, (const char *)data);
    return nbus_set_output(ctx, buf, len);
}

static nbus_cb_reg_t regs[] = {
    NBUS_DEF_METHOD(NBUS_PROTO_RAW, do_echo),
    NBUS_DEF_END()
};

void *main_server(__attribute__((unused)) void *arg)
{
    int r;
    struct pollfd fds[1];
    nbus_context_t *ctx;

    (void)arg;

    if ((r = nbus_init(&ctx, "server", regs, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        return NULL;
    }

    fds[0].fd = nbus_get_fd(ctx);
    fds[0].events = POLLIN | POLLHUP;

    /* Notify clients, we are ready to serve. */
    set_server_ready();

    printf("server\n");
    while ((poll(fds, 1, 1000) > 0) && is_running) {
        if (fds[0].revents & POLLIN) {
            if ((r = nbus_handle(ctx)) != 0) {
                fprintf(stderr, "nbus_handle: %s\n", strerror(r));
                break;
            }
        }
    }
    printf("server - exit\n");

    nbus_exit(ctx);

    return NULL;
}

void *main_client(__attribute__((unused)) void *arg)
{
    int r;
    nbus_context_t *ctx;
    uintptr_t me;

    char name[NBUS_CTX_ID_LEN];

    ctx = NULL;

    wait_server_ready();

    me = (uintptr_t)(void*)pthread_self();
    snprintf(name, NBUS_CTX_ID_LEN, "client-%lu", me);

    if ((r = nbus_init(&ctx, name, NULL, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        goto done;
    }

    printf("%s\n", name);
    while (is_running) {
        uint64_t ts;

        ts = clock_get_ts();
        r = nbus_invoke(ctx, 0, NBUS_PROTO_RAW, "server", "do_echo", "World", 5, NULL, NULL);
        if (r != 0) {
            fprintf(stderr, "nbus_invoke: %s\n", strerror(r));
            goto done;
        }
        msg_count_time(clock_get_ts() - ts);
    }
    printf("%s - exit\n", name);

done:
    nbus_exit(ctx);

    return NULL;
}
