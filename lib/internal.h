/* SPDX-License-Identifier: Apache-2.0 */

#ifndef NBUS__INTERNAL_H
#define NBUS__INTERNAL_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/un.h>

#include "nbus/nbus.h"

#if defined(__GNUC__) || defined(__clang__)
    #define F_INLINE                    __attribute__((always_inline)) __attribute__((flatten)) static __inline
#else
    #define F_INLINE                    static __inline
#endif

/**
 * \brief   Name used by the nBus Agent.
**/
#define NBUS_ID_AGENT                   "agent"

/**
 * \brief   Name used by the nBus CLI tool.
**/
#define NBUS_ID_CLI                     "cli"

#define NBF_DYNAMIC                     0x01
#define NBF_FIXED                       0x02

#define NBUS_FLAG_CALL_OK               ((uintptr_t)0x0100)
#define NBUS_FLAG_CALL_BAD              ((uintptr_t)0x0200)
#define NBUS_FLAG_NOREPLY               ((uintptr_t)0x0400)
#define NBUS_FLAG_META                  ((uintptr_t)0x0800)

#define NB__IS_RESERVED_ID(name) \
    ((strcmp(name, NBUS_ID_AGENT) == 0) || (strcmp(name, NBUS_ID_CLI) == 0))

#ifdef __cplusplus
extern "C" {
#endif

struct __bufr_s {
    uint8_t *data;
    size_t len, cap;
};

struct nbus_context_s {
    unsigned flags;
    char name[NBUS_CTX_ID_LEN];
    int fd;

    const nbus_cb_reg_t *regs;
    size_t n_regs;

    struct __bufr_s ingress;
    struct __bufr_s egress;
};

F_INLINE size_t nb__align_up(size_t n)
{
    size_t q, r;

    q = n / __SIZEOF_POINTER__;
    r = n % __SIZEOF_POINTER__;
    q = (q * __SIZEOF_POINTER__);
    if (r) {
        q += (__SIZEOF_POINTER__ - r);
    }

    return q;
}

#ifdef NBUS_PREFIX_IS_PATH
    #define nb__is_peer_chr(c)          ((isalnum(c) || c == '_' || c == '.'))
#else
    #define nb__is_peer_chr(c)          ((isalnum(c) || c == '_' || c == '.' || c == '/'))
#endif

#define nb__is_name_chr(c)              (isalnum(c) || c == '_')

F_INLINE int nb__is_valid_name(const char *str, int is_peer)
{
    const char *p;

    /* First character must be an alphabet. */
    if (!isalpha(*str)) return 0;

    if (is_peer && strlen(str) > NBUS_CTX_ID_LEN - 1) return 0;
    if (strlen(str) > NBUS_NAME_LEN - 1) return 0;

    /* test remaining characters  */
    for (p = str + 1; *p != 0; p++) {
        if (is_peer) {
            if (!nb__is_peer_chr(*p)) return 0;
        }
        else {
            if (!nb__is_name_chr(*p)) return 0;
        }
    }

    return 1;
}

typedef  struct {
    uintptr_t flags;
    uintptr_t len;
    char name[NBUS_NAME_LEN];
    char id[NBUS_CTX_ID_LEN];
} nb__qry_t;

typedef  struct {
    uintptr_t flags;
    uintptr_t len;
    intptr_t  err;
} nb__res_t;

typedef int (nbus__io_cb_t)(nbus_context_t *, uint64_t, const char *, nb__res_t *, nb__qry_t *);

int nb__init(nbus_context_t **r_ctx, int is_res, const char *name, const nbus_cb_reg_t *regs, void *buf, size_t *buf_len);

int nb__loop_remotes(nbus_context_t *ctx, int is_res, const char *pfx, const char *re, nbus__io_cb_t cb, void *arg);

int nb_do_egress(nbus_context_t *ctx, uint64_t ms, const char *dst, nb__res_t *res, nb__qry_t *qry);

#ifdef __cplusplus
}
#endif

#endif /* NBUS__INTERNAL_H */
