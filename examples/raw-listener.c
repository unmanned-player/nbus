#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>

#include "nbus/nbus.h"

static int hello_listener(nbus_context_t *ctx, uint8_t proto, const char *peer, const char *name, const void *data, const size_t n)
{
    (void)ctx;
    (void)proto;
    printf("E     = %s@%s\n", peer, name);
    printf("data  = %.*s\n", (int)n, (const char *)data);
    return 0;
}

static nbus_cb_reg_t regs[] = {
    NBUS_DEF_EVENT(NBUS_PROTO_ANY, "*", hello_listener),
    NBUS_DEF_END()
};

int main(void)
{
    int r;
    struct pollfd fds[2];
    static nbus_context_t *ctx;
    sigset_t mask;

    /* We will handle SIGTERM and SIGINT. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        perror("sigprocmask");
        return EXIT_FAILURE;
    }

    if ((r = nbus_init(&ctx, "listener", regs, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
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
