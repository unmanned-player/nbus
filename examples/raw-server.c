#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <signal.h>
#include <sys/signalfd.h>

#include <poll.h>
#include <unistd.h>

#include "nbus/nbus.h"

static int say_hello(nbus_context_t *ctx, uint8_t proto, const char *peer, const char *name, const void *data, const size_t n)
{
    char buf[256];
    size_t len;

    (void)proto;
    (void)peer;
    (void)name;

    printf("peer = %s\n", peer);

    len = snprintf(buf, sizeof(buf), "Hello, %.*s!", (int)n, (const char *)data);

    return nbus_set_output(ctx, buf, len);
}

static nbus_cb_reg_t regs[] = {
    NBUS_DEF_METHOD(NBUS_PROTO_RAW, say_hello),
    NBUS_DEF_END()
};

int main(void)
{
    int r;
    struct pollfd fds[2];
    nbus_context_t *ctx;
    sigset_t mask;

    /* We will handle SIGTERM and SIGINT. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        perror("sigprocmask");
        return EXIT_FAILURE;
    }

    if ((r = nbus_init(&ctx, "server", regs, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        return EXIT_FAILURE;
    }

    fds[0].fd = signalfd(-1, &mask, 0);
    fds[0].events = POLLIN | POLLHUP;

    fds[1].fd = nbus_get_fd(ctx);
    fds[1].events = POLLIN | POLLHUP;

    while (poll(fds, 2, -1) > 0) {
        if (fds[0].revents & POLLIN) {
            break; /* Got signal. */
        }
        if (fds[1].revents & POLLIN) {
            if ((r = nbus_handle(ctx)) != 0) {
                fprintf(stderr, "nbus_handle: %s\n", strerror(r));
                break;
            }
        }
    }

    nbus_exit(ctx);

    return 0;
}
