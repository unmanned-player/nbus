#include "speedtest.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <poll.h>
#include <unistd.h>

#include <libubox/blobmsg_json.h>
#include <libubus.h>

static __thread struct blob_buf b;

enum {
    ECHO_NAME,
    __ECHO_MAX
};

static const struct blobmsg_policy echo_policy[] = {
    [ECHO_NAME] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};

static int rpc_do_echo(
    struct ubus_context *ctx,
    struct ubus_object *obj,
    struct ubus_request_data *req,
    const char *method,
    struct blob_attr *msg
)
{
    struct blob_attr *tb[__ECHO_MAX];

    (void)obj;
    (void)method;

    blobmsg_parse(echo_policy, ARRAY_SIZE(echo_policy), tb, blob_data(msg), blob_len(msg));

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "data", blobmsg_get_string(tb[ECHO_NAME]));
    return ubus_send_reply(ctx, req, b.head);
}

static const struct ubus_method server_methods[] = {
    UBUS_METHOD("echo", rpc_do_echo, echo_policy),
};

static struct ubus_object_type server_object_type = UBUS_OBJECT_TYPE("server", server_methods);

static struct ubus_object server_object = {
    .name      = "server",
    .type      = &server_object_type,
    .methods   = server_methods,
    .n_methods = ARRAY_SIZE(server_methods),
};

void *main_server(void *arg)
{
    struct ubus_context *ubus_ctx;
    struct pollfd fds[1]; /* 0 - ubus, 1 - timer. */
    int ret;

    (void)arg;

    if ((ubus_ctx = ubus_connect(NULL)) == NULL) {
        fprintf(stderr, "UBus daemon not running?\n");
        is_running = 0;
        return NULL;
    }

    if ((ret = ubus_add_object(ubus_ctx, &server_object)) != 0) {
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
        return NULL;
    }

    fds[0].fd = ubus_ctx->sock.fd;
    fds[0].events = POLLIN | POLLHUP;

    set_server_ready();

    while (is_running) {
        if (poll(fds, 1, 1000) > 0 && (fds[0].revents & POLLIN) != 0) {
            ubus_handle_event(ubus_ctx);
        }
    }

    return NULL;
}

void *main_client(void *arg)
{
    struct ubus_context *ubus_ctx;
    uint32_t id; /* server's ID */
    int ret;
    char data[256];
    uintptr_t me;

    (void)arg;

    wait_server_ready();

    if ((ubus_ctx = ubus_connect(NULL)) == NULL) {
        fprintf(stderr, "UBus daemon not running?\n");
        is_running = 0;
        return NULL;
    }

    while (is_running && ubus_lookup_id(ubus_ctx, "server", &id) != 0) {
        sleep(1);
    }

    me = (uintptr_t)(void*)pthread_self();
    printf("client-%lu\n", me);

    while (is_running) {
        uint64_t ts;

        ts = clock_get_ts();
        blob_buf_init(&b, 0);
        snprintf(data, sizeof(data), "%" PRIu64, ts);
        blobmsg_add_string(&b, "data", data);
        if ((ret = ubus_invoke(ubus_ctx, id, "echo", b.head, NULL, 0, 5000)) == 0) {
            msg_count_time(clock_get_ts() - ts);
        }
        else {
            printf("failed: %s\n", ubus_strerror(ret));
            is_running = 0;
        }
    }

    return NULL;
}
