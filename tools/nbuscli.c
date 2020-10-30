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

#define HDR_FMT_ANSI                    "\n" ANSI_CYAN "> " ANSI_MAGENTA "[%c] " ANSI_GREEN NBUS_CTX_NAME_PREFIX ANSI_NORMAL "%s" ANSI_YELLOW "@" ANSI_NORMAL "%s (%zu)\n"
#define HDR_FMT_RAW                     "\n> [%c] " NBUS_CTX_NAME_PREFIX "%s@%s (%zu)\n"

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

char *peer = NULL;
char *method = NULL;
char *event = NULL;
uint8_t proto = NBUS_PROTO_ANY;
unsigned counter = 0;
unsigned verbose = 0;
char *arg = NULL;
size_t arg_len = 0;
int no_arg = 0, need_reply = 0;

int is_stdout_tty = 0;

F_INLINE char nb__proto_chr(uint8_t _p)
{
    switch (_p) {
        case NBUS_PROTO_RAW:    return 'R';
        case NBUS_PROTO_CBOR:   return 'C';
        case NBUS_PROTO_JSON:   return 'J';
        default:                break;
    }
    return 'X';
}

static void nb__main_help(void)
{
    printf(
        "nBus Diagnostic Utility v" PROG_VERSION "\n"
        "\n"
        "Usage: nbuscli [command] [options]\n"
        "\n"
        "  -h, --help       This help message.\n"
        "  -v, --verbose    Version string.\n"
        "\n"
        "Commands:\n"
        "  list             Show a list of peers.\n"
        "  listen           Listen to events.\n"
        "  invoke           Invoke a remote method.\n"
        "  raise            Raise an event.\n"
        "\n"
        "Use `-h` option in each of these sub-commands to get more details.\n"
        "\n"
        "Copyright (c) 2020 nBus\n"
    );
}

static void nb__invoke_help(void)
{
    printf(
        "nBus - RPC invoker\n"
        "\n"
        "Usage: nbuscli invoke [options]\n"
        "\n"
        "  -h, --help           This help message.\n"
        "\n"
        "  -p, --peer           Name of remote peer on which to invoke.\n"
        "  -P, --protocol       Serialisation protocol to use.\n"
        "  -m, --method         Name of remote method.\n"
        "  -n, --no-args        Call remote function without arguments.\n"
        "  -w, --wait-reply     Wait for reply.\n"
        "  -i, --file <FILE>    Arguments to pass read from file.\n"
        "\n"
        "If `--no-args` is not given and `--file` is also not given, arguments\n"
        "are taken from STDIN.\n"
        "\n"
        "Copyright (c) 2020 nBus\n"
    );
}

static void nb__list_help(void)
{
    printf(
        "nBus - Peer listing\n"
        "\n"
        "Usage: nbuscli list [-v]\n"
        "\n"
        "\n"
        "  -h, --help       This help message.\n"
        "\n"
        "  -v, --verbose    Verbose listing of remote methods and event handlers.\n"
        "\n"
        "Copyright (c) 2020 nBus\n"
    );
}

static void nb__listen_help(void)
{
    printf(
        "nBus - Events listener\n"
        "\n"
        "Usage: nbuscli listen [-v] [-p peer] [-P protocol] [-e event]\n"
        "\n"
        "\n"
        "  -h, --help       This help message.\n"
        "\n"
        "  -P, --protocol   Serialisation protocol to listen to.\n"
        "  -p, --peer       Either a single peer or a wild-card.\n"
        "  -e, --event      Specific event or a wild-card filter.\n"
        "\n"
        "Note, both `peer` and `event` default '*' if not specified.\n"
    );
}

static void nb__raise_help(void)
{
    printf(
        "nBus - Raise event on remote peers\n"
        "\n"
        "Usage: nbuscli raise [options]\n"
        "\n"
        "  -h, --help       This help message.\n"
        "\n"
        "  -P, --protocol   Serialisation protocol to use.\n"
        "  -e, --event      Name of event.\n"
        "  -n, --no-args    No contents/arguments to the event.\n"
        "  -i, --file       Arguments/Contents of the event.\n"
        "\n"
        "Copyright (c) 2020 nBus\n"
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
        ? nbus_invoke(ctx, 0, NBUS_PROTO_RAW, peer, method, arg, arg_len, nb__reply_handler, NULL)
        : nbus_invoke(ctx, 0, NBUS_PROTO_RAW, peer, method, arg, arg_len, NULL, NULL);

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
    (void)q;

    printf("  %s\n", (_peer[0] == '/')? (_peer + sizeof(NBUS_CTX_NAME_PREFIX)): _peer);
    if (verbose && nb_do_egress(ctx, ms, _peer, &mres, &meta) == 0) {
        size_t i, n_regs;
        nbus_cb_reg_t *reg;

        n_regs = mres.len / sizeof(nbus_cb_reg_t);
        for (i = 0, reg = (nbus_cb_reg_t *)ctx->ingress.data; i < n_regs; i++, reg++) {
            char flags[] = ".. X";

            if ((reg->flags & NBUS_KIND_METHOD) != 0) {
                flags[0] = 'M';
            }
            else if ((reg->flags & NBUS_KIND_EVENT) != 0) {
                flags[1] = 'E';
            }

            if (is_stdout_tty) {
                printf("    " ANSI_MAGENTA "[%s]" ANSI_NORMAL " %s\n", flags, reg->name);
            }
            else {
                printf("    [%s] %s\n", flags, reg->name);
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
        fprintf(f_mem, HDR_FMT_ANSI, nb__proto_chr(_p), _peer, _evt, n);
    }
    else {
        fprintf(f_mem, HDR_FMT_RAW, nb__proto_chr(_p), _peer, _evt, n);
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
        nb__main_help();
        return EXIT_FAILURE;
    }
    else {
        c_argv = &argv[1];
        c_argc = argc - 1;
    }

    is_stdout_tty = isatty(STDOUT_FILENO);

    if (strcasecmp(argv[1], "invoke") == 0) {
        struct option opts_invoke[] = {
            { "help",       no_argument,        NULL, 'h' },
            { "no-args",    no_argument,        NULL, 'n' },
            { "wait-reply", no_argument,        NULL, 'w' },
            { "protocol",   required_argument,  NULL, 'P' },
            { "peer",       required_argument,  NULL, 'p' },
            { "method",     required_argument,  NULL, 'm' },
            { "file",       required_argument,  NULL, 'i' },

            { NULL,         0,                  NULL,  0  },
        };

        proto = NBUS_PROTO_RAW;
        while ((c = getopt_long(c_argc, c_argv, "hnwP:p:m:i:", opts_invoke, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__invoke_help();
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
        nb__invoke();
    }
    else if (strcasecmp(argv[1], "list") == 0) {
        struct option opts_list[] = {
            { "help",       no_argument,        NULL, 'h' },
            { "verbose",    no_argument,        NULL, 'v' },

            { NULL,         0,                  NULL,  0  },
        };

        while ((c = getopt_long(c_argc, c_argv, "hv", opts_list, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__list_help();
                    return EXIT_SUCCESS;

                case 'v':
                    verbose = 1;
                    break;

                default:
                    break;
            }
        }

        nb__list();
    }
    else if (strcasecmp(argv[1], "listen") == 0) {
        struct option opts_listen[] = {
            { "help",       no_argument,        NULL, 'h' },
            { "event",      required_argument,  NULL, 'e' },
            { "peer",       required_argument,  NULL, 'p' },
            { "protocol",   required_argument,  NULL, 'P' },

            { NULL,         0,                  NULL,  0  },
        };

        while ((c = getopt_long(c_argc, c_argv, "he:p:P:", opts_listen, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__listen_help();
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
        struct option opts_raise[] = {
            { "help",       no_argument,        NULL, 'h' },
            { "no-args",    no_argument,        NULL, 'n' },
            { "protocol",   required_argument,  NULL, 'P' },
            { "event",      required_argument,  NULL, 'e' },
            { "file",       required_argument,  NULL, 'i' },

            { NULL,         0,                  NULL,  0  },
        };

        proto = NBUS_PROTO_RAW;
        peer = strdup("*");

        while ((c = getopt_long(c_argc, c_argv, "hnP:e:i:", opts_raise, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__raise_help();
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
        struct option opts_main[] = {
            { "help",       no_argument,        NULL, 'h' },
            { "version",    no_argument,        NULL, 300 },

            { NULL,         0,                  NULL,  0  },
        };

        while ((c = getopt_long(c_argc, c_argv, "hv", opts_main, &idx)) != -1) {
            switch (c) {
                case 'h':
                    nb__main_help();
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
