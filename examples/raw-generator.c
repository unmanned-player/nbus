#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <signal.h>
#include <unistd.h>

#include "nbus/nbus.h"

#define MSG_RAW             "World!"
#define MSG_JSON            "{ \"data\": \"World!\" }\0"

/* textString: World! */
static const uint8_t MSG_CBOR[] = { 0x66, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };

static volatile int is_running = 1;

static void sig__breaker(int signo)
{
    (void)signo;
    is_running = 0;
}

int main(void)
{
    int r;
    static nbus_context_t *ctx;

    signal(SIGINT,  sig__breaker);
    signal(SIGTERM, sig__breaker);
    signal(SIGHUP,  sig__breaker);

    if ((r = nbus_init(&ctx, "generator", NULL, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
    }

    /* Raise an event once every second. */
    while(is_running) {
        r = nbus_raise_event(ctx, NBUS_PROTO_RAW,  "*", "hello_raw",  MSG_RAW,  sizeof(MSG_RAW) - 1);
        r = nbus_raise_event(ctx, NBUS_PROTO_JSON, "*", "hello_json", MSG_JSON, sizeof(MSG_JSON));
        r = nbus_raise_event(ctx, NBUS_PROTO_CBOR, "*", "hello_cbor", MSG_CBOR, sizeof(MSG_CBOR));
        sleep(1);
    }
    if (r != 0) fprintf(stderr, "nbus_raise_event = %s\n", strerror(r));

    nbus_exit(ctx);

    return 0;
}
