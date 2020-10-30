#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>

#include "nbus/nbus.h"

__attribute__((unused))
static void hello_reply(uint8_t proto, int rc, void *extra, const void *data, size_t n)
{
    int *out;

    out = (int *)extra;

    (void)proto;
    (void)rc;

    if (n != 13 || strncmp((const char *)data, "Hello, World!", n) != 0) {
        fprintf(stdout, "Unexpected: res_len = %zu, data = %s\n", n, (const char *)data);
        *out = 1;
    }
}

int main(void)
{
    int r, rc;
    nbus_context_t *ctx;

    ctx = NULL;

    if ((r = nbus_init(&ctx, "client", NULL, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        goto done;
    }

    rc = 0;
    r = nbus_invoke(ctx, 0, NBUS_PROTO_RAW, "server", "say_hello", "World", 5, hello_reply, &rc);
    /* Now comment the above line, uncomment the line below to see how it works when you don't expect a reply. */
    // r = nbus_invoke(ctx, 0, NBUS_PROTO_RAW, "server", "say_hello", "World", 5, NULL, NULL);
    if (r != 0) {
        fprintf(stderr, "nbus_invoke: %s\n", strerror(r));
        goto done;
    }

    if (rc != 0) {
        fprintf(stderr, "say_hello: %s\n", strerror(r));
        goto done;
    }

    r = 0;

done:
    nbus_exit(ctx);

    return r;
}
