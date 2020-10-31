/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

#include <signal.h>
#include <fnmatch.h>
#include <getopt.h>
#include <poll.h>
#include <unistd.h>
#include <sys/signalfd.h>

#include "nbus/nbus.h"

#include "internal.h"

#ifdef NB__HAS_JSON
    #include <json-c/json.h>
#endif

#ifdef NB__HAS_CBOR
    #include <tinycbor/cbor.h>
#endif

#define ANSI_NORMAL                     "\x1B[0m"
#define ANSI_RED                        "\x1B[31m"
#define ANSI_GREEN                      "\x1B[32m"
#define ANSI_YELLOW                     "\x1B[33m"
#define ANSI_BLUE                       "\x1B[34m"
#define ANSI_MAGENTA                    "\x1B[35m"
#define ANSI_CYAN                       "\x1B[36m"
#define ANSI_WHITE                      "\x1B[37m"

#define HDR_FMT_ANSI                    "\n" ANSI_CYAN "> " ANSI_MAGENTA "[%s] " ANSI_GREEN NBUS_CTX_NAME_PREFIX ANSI_NORMAL "%s" ANSI_YELLOW "@" ANSI_NORMAL "%s (%zu)\n"
#define HDR_FMT_RAW                     "\n> [%s] " NBUS_CTX_NAME_PREFIX "%s@%s (%zu)\n"

#define ARG_EVENT                       { "event",      required_argument,  NULL, 'e' }
#define ARG_HELP                        { "help",       no_argument,        NULL, 'h' }
#define ARG_INPUT                       { "input",      required_argument,  NULL, 'i' }
#define ARG_METHOD                      { "method",     required_argument,  NULL, 'm' }
#define ARG_NO_ARGS                     { "no-args",    no_argument,        NULL, 'n' }
#define ARG_PEER                        { "peer",       required_argument,  NULL, 'p' }
#define ARG_PROTOCOL                    { "protocol",   required_argument,  NULL, 'P' }
#define ARG_TIMEOUT                     { "timeout",    required_argument,  NULL, 't' }
#define ARG_VERBOSE                     { "verbose",    no_argument,        NULL, 'v' }
#define ARG_VERSION                     { "version",    no_argument,        NULL, 300 }
#define ARG_WAIT                        { "wait-reply", no_argument,        NULL, 'w' }
#define ARG_END                         { NULL,         0,                  NULL,  0  }

#define SOPT_INVOKE                     "hi:m:np:P:t:w"
#define SOPT_LIST                       "hv"
#define SOPT_LISTEN                     "he:p:P:"
#define SOPT_RAISE                      "hnP:e:i:t:"
#define SOPT_MAIN                       "h"

static struct option opts_main[] = {
    ARG_HELP,
    ARG_VERSION,
    ARG_END
};

static struct option opts_invoke[] = {
    ARG_HELP,
    ARG_INPUT,
    ARG_METHOD,
    ARG_NO_ARGS,
    ARG_PEER,
    ARG_PROTOCOL,
    ARG_TIMEOUT,
    ARG_WAIT,
    ARG_END
};

static struct option opts_list[] = {
    ARG_HELP,
    ARG_VERBOSE,
    ARG_END
};

static struct option opts_listen[] = {
    ARG_HELP,
    ARG_EVENT,
    ARG_PEER,
    ARG_PROTOCOL,
    ARG_END
};

static struct option opts_raise[] = {
    ARG_EVENT,
    ARG_HELP,
    ARG_INPUT,
    ARG_NO_ARGS,
    ARG_PROTOCOL,
    ARG_END
};

#define nb__accept_name(V, wc, is_peer)                                         \
    do {                                                                        \
        if (V) free(V);                                                         \
        V = strdup(optarg);                                                     \
                                                                                \
        if (!wc && !nb__is_valid_name(optarg, is_peer)) {                       \
            fprintf(stderr, "nbuscli: Invalid " #V " name - '%s'.\n", optarg);  \
            exit(EXIT_FAILURE);                                                 \
        }                                                                       \
    } while (0)

static char *peer = NULL;
static char *method = NULL;
static char *event = NULL;
static uint8_t proto = NBUS_PROTO_ANY;
static unsigned counter = 0;
static unsigned verbose = 0;
static char *arg = NULL;
static size_t arg_len = 0;
static int no_arg = 0, need_reply = 0;
static uint64_t timeout = 0;

#ifdef NB__HAS_JSON
static struct json_tokener *json_tok = NULL;
#endif

int is_stdout_tty = 0;

F_INLINE const char *nb__proto_str(uint8_t _p)
{
    static char buf[4] = { 0, 0, 0, 0 };

    switch (_p) {
        case NBUS_PROTO_ANY:
            buf[0] = ' '; buf[1] = '*';
            break;
        case NBUS_PROTO_RAW:
            buf[0] = ' '; buf[1] = 'R';
            break;
        case NBUS_PROTO_CBOR:
            buf[0] = ' '; buf[1] = 'C';
            break;
        case NBUS_PROTO_JSON:
            buf[0] = ' '; buf[1] = 'J';
            break;
        default:
            snprintf(buf, sizeof(buf), "%02x", _p);
            break;
    }
    return buf;
}

static void nb__help(void)
{
    printf(
        "nBus Diagnostic Utility v" PROG_VERSION "\n"
        "\n"
        "Usage:\n"
        "  nbuscli invoke [-w] -p <N> -m <N> [-P <P>] [-t <MS>] (-i <FILE> | -n)\n"
        "  nbuscli list [-v]\n"
        "  nbuscli listen -e <N|W> -p <N|W> [-P <P>]\n"
        "  nbuscli raise -e <N> [-P <P>] [-t <MS>] (-i <FILE> | -n)\n"
        "\n"
        "  -h, --help       This help message\n"
        "      --version    Version string\n"
        "\n"
        "Commands:\n"
        "  invoke   Invoke a remote method\n"
        "  list     Show live peers\n"
        "  listen   Listen for public events\n"
        "  raise    Raise an event\n"
        "\n"
        "Options:\n"
        "  -e, --event <N|W>    Event name or wild-card filter\n"
        "  -i, --input <FILE>   Load arguments from file\n"
        "  -m, --method <N>     Method name\n"
        "  -n, --no-args        Do not expect arguments\n"
        "  -p, --peer <N|W>     Peer name or wild-card filter\n"
        "  -P, --protocol <P>   Select serialisation protocol\n"
        "  -t, --timeout <MS>   Timeout in milliseconds\n"
        "  -w, --wait-reply     Wait for reply after invocation\n"
        "  -v, --verbose        Show more drama\n"
        "\n"
        "Where,\n"
        "  <N>      A valid name\n"
        "  <W>      wild-card filter\n"
        "  <P>      Protocol code or one of 'raw', 'cbor', 'json'\n"
        "\n"
        "Copyright (c) 2020 nBus Unmanned Player\n"
    );
}

static void nb__show_version(void)
{
    printf(
        "nBus Diagnostic Utility v" PROG_VERSION "\n"
    );
}

static void nb__parse_proto(int allow_any)
{
    char *t;
    long v;

    t = NULL;

    if (strcasecmp(optarg, "raw") == 0) {
        proto = NBUS_PROTO_RAW;
    }
    else if (strcasecmp(optarg, "cbor") == 0) {
        proto = NBUS_PROTO_CBOR;
    }
    else if (strcasecmp(optarg, "json") == 0) {
        proto = NBUS_PROTO_JSON;
    }
    else {
        v = strtol(optarg, &t, 0);
    }

    proto = (t == optarg || *t != '\0' || ((v == LONG_MIN || v == LONG_MAX) && errno == ERANGE))
            ? NBUS_PROTO_ANY
            : (uint8_t)v;

    if (!allow_any && proto == NBUS_PROTO_ANY) {
        fprintf(stderr, "nbuscli: Invalid protocol - '%s'.\n", optarg);
        exit(EXIT_FAILURE);
    }
}

static void nb__load_args(FILE *f_in)
{
    FILE *f_arg;

    if (!no_arg && f_in == NULL) {
        f_in = stdin;
    }

    if (f_in) {
        char dat[512] = {0};
        ssize_t rd;

        f_arg = open_memstream(&arg, &arg_len);
        while ((rd = fread(dat, 1, sizeof(dat), f_in)) > 0) {
            fwrite(dat, 1, rd, f_arg);
        }
        fclose(f_arg);
        fclose(f_in);
    }
}

static void nb__reply_handler(uint8_t _p, int rc, void *extra, const void *data, size_t n)
{
    (void)_p;
    (void)rc;
    (void)extra;

    fwrite(data, n, 1, stdout);
}

static void nb__invoke(void)
{
    int r;
    nbus_context_t *ctx = NULL;

    if ((r = nb__init(&ctx, 1, NBUS_ID_CLI, NULL, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }

    r = (need_reply)
        ? nbus_invoke(ctx, timeout, NBUS_PROTO_RAW, peer, method, arg, arg_len, nb__reply_handler, NULL)
        : nbus_invoke(ctx, timeout, NBUS_PROTO_RAW, peer, method, arg, arg_len, NULL, NULL);

    nbus_exit(ctx);

    if (r) {
        fprintf(stderr, "nbuscli invoke: %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }
}

static int nb__peer_printer(nbus_context_t *ctx, uint64_t ms, const char *_peer, nb__res_t *r, nb__qry_t *q)
{
    nb__qry_t meta = { .flags = NBUS_FLAG_META };
    nb__res_t mres;

    (void)r;
    (void)ms;
    (void)q;

    printf("  %s\n", (_peer[0] == '/')? (_peer + sizeof(NBUS_CTX_NAME_PREFIX)): _peer);
    if (verbose && nb_do_egress(ctx, timeout, _peer, &mres, &meta) == 0) {
        size_t i, n_regs;
        nbus_cb_reg_t *reg;

        n_regs = mres.len / sizeof(nbus_cb_reg_t);
        for (i = 0, reg = (nbus_cb_reg_t *)ctx->ingress.data; i < n_regs; i++, reg++) {
            char flags[] = "..";

            if ((reg->flags & NBUS_KIND_METHOD) != 0) {
                flags[0] = 'M';
            }
            else if ((reg->flags & NBUS_KIND_EVENT) != 0) {
                flags[1] = 'E';
            }

            if (is_stdout_tty) {
                printf("    " ANSI_MAGENTA "[%s %s]" ANSI_NORMAL " %s\n", flags, nb__proto_str(reg->flags), reg->name);
            }
            else {
                printf("    [%s %s] %s\n", flags, nb__proto_str(reg->flags), reg->name);
            }
        }
    }

    counter++;

    return 0;
}

static void nb__list(void)
{
    int r;
    nbus_context_t *ctx = NULL;

    if ((r = nb__init(&ctx, 1, NBUS_ID_CLI, NULL, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }

    if ((r = nb__loop_remotes(ctx, 1, NBUS_CTX_NAME_PREFIX, "*", nb__peer_printer, NULL)) != 0) {
        fprintf(stderr, "Something went wrong while listing peers. %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }

    nbus_exit(ctx);
}

static void dump_rawc(FILE *f_mem, const void *data, const size_t n)
{
    size_t i;
    unsigned char glyphs[17];
    const uint8_t *pc = (const uint8_t *)data;

    (void)f_mem;
    (void)data;
    (void)n;

    memset(glyphs, 0, sizeof(glyphs));

    for (i = 0; i < n; i++) {
        if ((i % 16) == 0) {
            if (i != 0) {
                fprintf(f_mem, " %s\n", glyphs);
            }
            fprintf(f_mem, "  %04zx ", i);
        }
        fprintf(f_mem, " %02x", pc[i]);

        glyphs[i % 16] = isprint(pc[i])? pc[i]: '.';
        glyphs[(i % 16) + 1] = '\0';
    }

    /* Pad out last line if not exactly 16 characters. */
    while ((i % 16) != 0) {
        fprintf(f_mem, "   ");
        i++;
    }
    fprintf(f_mem, "  %s\n", glyphs);
}

#ifdef NB__HAS_CBOR
static void dump_cbor(FILE *f_mem, const void *data, const size_t n)
{
    CborParser cbor_parser; /* parser. */
    CborValue cbor_it; /* value iterator */

    (void)f_mem;
    (void)data;
    (void)n;

    if (cbor_parser_init(data, n, 0, &cbor_parser, &cbor_it) == CborNoError) {
        while (!cbor_value_at_end(&cbor_it)) {
            cbor_value_to_pretty(f_mem, &cbor_it);
            cbor_value_advance(&cbor_it);
        }
    }
    fprintf(f_mem, "\n");
}
#endif

#ifdef NB__HAS_JSON
static void dump_json(FILE *f_mem, const void *data, const size_t n)
{
    struct json_object *json;

    json = json_tokener_parse_ex(json_tok, data, n);
    fprintf(f_mem, "%s\n", json_object_to_json_string_ext(json, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
}
#endif

static int nb_show_anye(nbus_context_t *ctx, uint8_t _p, const char *_peer, const char *_evt, const void *data, const size_t n)
{
    FILE *f_mem;
    char *bufr;
    size_t buf_n;

    (void)ctx;

    /* Do some filtering... */
    if (event != NULL && fnmatch(event, _evt, 0) != 0) {
        return 0;
    }
    if (peer != NULL && fnmatch(peer, _peer, 0) != 0) {
        return 0;
    }
    if (proto != 0 && proto != _p) {
        return 0;
    }

    bufr  = NULL;
    buf_n = 0;
    f_mem = open_memstream(&bufr, &buf_n);

    if (is_stdout_tty) {
        fprintf(f_mem, HDR_FMT_ANSI, nb__proto_str(_p), _peer, _evt, n);
    }
    else {
        fprintf(f_mem, HDR_FMT_RAW, nb__proto_str(_p), _peer, _evt, n);
    }

    if (_p == NBUS_PROTO_RAW) {
        dump_rawc(f_mem, data, n);
    }
    else if (_p == NBUS_PROTO_CBOR) {
    #ifdef NB__HAS_CBOR
        dump_cbor(f_mem, data, n);
    #else
        dump_rawc(f_mem, data, n);
    #endif
    }
    else if (_p == NBUS_PROTO_JSON) {
    #ifdef NB__HAS_JSON
        dump_json(f_mem, data, n);
    #else
        dump_rawc(f_mem, data, n);
    #endif
    }
    else {
        /* Unknown protocol, so hex dump. */
        dump_rawc(f_mem, data, n);
    }

    fclose(f_mem);
    write(STDOUT_FILENO, bufr, buf_n);
    free(bufr);

    counter++;

    return 0;
}

static void nb__listen(void)
{
    static nbus_cb_reg_t regs[] = {
        NBUS_DEF_EVENT(0, "*", nb_show_anye),
        NBUS_DEF_END()
    };
    int r;
    nbus_context_t *ctx = NULL;
    struct pollfd fds[2];
    sigset_t mask;

    /* We will handle SIGTERM and SIGINT. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

#ifdef NB__HAS_JSON
    json_tok = json_tokener_new();
#endif

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        fprintf(stderr, "sigprocmask: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((r = nb__init(&ctx, 1, NBUS_ID_CLI, regs, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }

    fds[0].fd = nbus_get_fd(ctx);
    fds[0].events = POLLIN | POLLHUP;

    fds[1].fd = signalfd(-1, &mask, 0);
    fds[1].events = POLLIN | POLLHUP;

    while (poll(fds, 2, -1) > 0) {
        if (fds[0].revents & POLLIN) {
            if ((r = nbus_handle(ctx)) != 0) {
                fprintf(stderr, "nbus_handle: %s\n", strerror(r));
                break;
            }
        }
        else if (fds[1].revents & POLLIN) {
            break; /* Got signal. */
        }
    }

    fprintf(stdout, "\nListened to %u events.\n", counter);

#ifdef NB__HAS_JSON
    json_tokener_free(json_tok);
#endif
    nbus_exit(ctx);
}

static void nb__raise(void)
{
    int r;
    nbus_context_t *ctx;

    if ((r = nb__init(&ctx, 1, NBUS_ID_CLI, NULL, NULL, NULL)) != 0) {
        fprintf(stderr, "nbus_init: %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }

    r = nbus_raise_event(ctx, proto,  peer, event, arg, arg_len);

    nbus_exit(ctx);

    if (r) {
        fprintf(stderr, "nbuscli raise: %s\n", strerror(r));
        exit(EXIT_FAILURE);
    }
}

F_INLINE uint64_t str2i(void)
{
    char *t;
    unsigned long long int v;

    errno = 0;
    v = strtoull(optarg, &t, 0);
    if (t == optarg || *t != '\0' || ((v == 0 || v == UINT64_MAX) && errno == ERANGE)) {
        return 500;
    }
    else {
        return v;
    }
}

int main(int argc, char **argv)
{
    int c, idx;
    FILE *f_in = NULL;

    int c_argc = argc;
    char **c_argv = argv;

    optarg = NULL;
    idx = 0;

    if (argc < 2) {
        fprintf(stderr, "Needs a sub-command\n");
        nb__help();
        return EXIT_FAILURE;
    }
    else {
        c_argv = &argv[1];
        c_argc = argc - 1;
    }

    is_stdout_tty = isatty(STDOUT_FILENO);

    if (strcasecmp(argv[1], "invoke") == 0) {
        proto = NBUS_PROTO_RAW;
        while ((c = getopt_long(c_argc, c_argv, SOPT_INVOKE, opts_invoke, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__help();
                    return EXIT_SUCCESS;

                case 'n':
                    no_arg = 1;
                    break;

                case 'w':
                    need_reply = 1;
                    break;

                case 'P':
                    nb__parse_proto(0);
                    break;

                case 'p':
                    nb__accept_name(peer, 0, 1);
                    break;

                case 'm':
                    nb__accept_name(method, 0, 0);
                    break;

                case 't':
                    timeout = str2i();
                    break;

                case 'i':
                    if (f_in) fclose(f_in);
                    if ((f_in = fopen(optarg, "r")) == NULL) {
                        fprintf(stderr, "nbuscli: Unable to open arguments file '%s'. %s.\n", optarg, strerror(errno));
                        return EXIT_FAILURE;
                    }
                    break;

                default: break;
            }
        }
        nb__load_args(f_in);
        if (timeout) need_reply = 1;
        nb__invoke();
    }
    else if (strcasecmp(argv[1], "list") == 0) {
        while ((c = getopt_long(c_argc, c_argv, SOPT_LIST, opts_list, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__help();
                    return EXIT_SUCCESS;

                case 'v':
                    verbose = 1;
                    break;

                case 't':
                    timeout = str2i();
                    break;

                default:
                    break;
            }
        }

        if (timeout == 0) timeout = 500; /* Force half a millisecond to prevent failures. */
        nb__list();
    }
    else if (strcasecmp(argv[1], "listen") == 0) {
        proto = NBUS_PROTO_ANY;
        while ((c = getopt_long(c_argc, c_argv, SOPT_LISTEN, opts_listen, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__help();
                    return EXIT_SUCCESS;

                case 'e':
                    nb__accept_name(event, 0, 0);
                    break;

                case 'p':
                    nb__accept_name(peer, 0, 0);
                    break;

                case 'P':
                    nb__parse_proto(1);
                    break;

                default:
                    break;
            }
        }

        nb__listen();
    }
    else if (strcasecmp(argv[1], "raise") == 0) {
        proto = NBUS_PROTO_RAW;
        peer = strdup("*");

        no_arg = 0;
        while ((c = getopt_long(c_argc, c_argv, SOPT_RAISE, opts_raise, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__help();
                    return EXIT_SUCCESS;

                case 'n':
                    no_arg = 1;
                    break;

                case 'P':
                    nb__parse_proto(1);
                    break;

                case 'e':
                    nb__accept_name(event, 0, 0);
                    break;

                case 'i':
                    if (f_in) fclose(f_in);
                    if ((f_in = fopen(optarg, "r")) == NULL) {
                        fprintf(stderr, "nbuscli: Unable to open arguments file '%s'. %s.\n", optarg, strerror(errno));
                        return EXIT_FAILURE;
                    }
                    break;

                default:
                    break;
            }
        }

        nb__load_args(f_in);
        nb__raise();
    }
    else {
        while ((c = getopt_long(argc, argv, SOPT_MAIN, opts_main, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__help();
                    return EXIT_SUCCESS;

                case 300:
                    nb__show_version();
                    return EXIT_SUCCESS;

                default:
                    break;
            }
        }
    }

    if (arg) {
        free(arg);
    }

    return 0;
}
