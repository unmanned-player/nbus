/* SPDX-License-Identifier: Apache-2.0 */

#include <errno.h>

#include <stdio.h>
#include <fnmatch.h>
#include <dirent.h>
#include <string.h>

#include <sys/time.h>
#include <sys/stat.h>

#include "internal.h"

#define NB__CTX_LEN                     nb__align_up(sizeof(nbus_context_t))

F_INLINE void nb__make_addr(struct sockaddr_un *addr, socklen_t *len, const char *name)
{
    memset(addr, 0, sizeof(struct sockaddr_un));
    addr->sun_family = AF_UNIX;
#ifdef NBUS_PREFIX_IS_PATH
    if (name[0] == '/') {
        strncpy(addr->sun_path, name, sizeof(addr->sun_path));
    }
    else {
        snprintf(addr->sun_path, sizeof(addr->sun_path), NBUS_CTX_NAME_PREFIX "%s", name);
    }
#else
    snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, NBUS_CTX_NAME_PREFIX "%s", name);
#endif
    *len = sizeof(struct sockaddr_un);
}

F_INLINE int nb__grow_sb(uintptr_t flag, struct __bufr_s *sb, size_t extra)
{
    size_t _t;
    void *_np;

    if (extra >= sb->cap) {
        if ((flag & NBF_FIXED) != 0) {
            return ENOBUFS;
        }
        _t  = nb__align_up(extra);
        if ((_np = realloc(sb->data, _t)) != NULL) {
            sb->data = _np;
            sb->cap  = _t;
        }
        else {
            return ENOMEM;
        }
    }
    return 0;
}

F_INLINE size_t nb__get_so_buflen(int fd)
{
    int is_local;
    int size;
    socklen_t len;

    is_local = 0;
    if (fd == -1) {
        is_local = 1;
        if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            return 0;
        }
    }

    len = sizeof(size);
    size = 0;
    if ((getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, &len)) == -1) {
        size = 0;
    }

#if defined(__linux__) || defined(__linux) || defined(linux)
    /* See https://www.mankier.com/7/socket */
    size /= 2;
#endif

    if (is_local) {
        close(fd);
    }

    return (size_t)size;
}

static const nbus_cb_reg_t *nb__find_func(nbus_context_t *ctx, const char *name, uintptr_t flags)
{
    const nbus_cb_reg_t *p;

    for (p = ctx->regs; p && p->flags != 0; p++) {
        if ((p->flags & NBUS_KIND_METHOD) != 0 && NB_PROTO_ID(p->flags) == NB_PROTO_ID(flags)) {
            if (strncmp(p->name, name, NBUS_NAME_LEN) == 0) {
                return p;
            }
        }
    }

    return NULL;
}

static const nbus_cb_reg_t *nb__find_event(nbus_context_t *ctx, const char *name, uintptr_t flags)
{
    const nbus_cb_reg_t *p;

    /* Search for matching protocol first.. */
    for (p = ctx->regs; p && p->flags != 0; p++) {
        if ((p->flags & NBUS_KIND_EVENT) != 0 && NB_PROTO_ID(p->flags) == NB_PROTO_ID(flags)) {
            if (fnmatch(p->name, name, 0) == 0) {
                return p;
            }
        }
    }
    /* If that didn't work, search for any protocol. */
    for (p = ctx->regs; p && p->flags != 0; p++) {
        if ((p->flags & NBUS_KIND_EVENT) != 0 && NB_PROTO_ID(p->flags) == 0) {
            if (fnmatch(p->name, name, 0) == 0) {
                return p;
            }
        }
    }

    return NULL;
}

F_INLINE bool nb__needs_reply(uintptr_t flags)
{
    return (((flags & NBUS_KIND_METHOD) || (flags & NBUS_FLAG_META)) != 0) && ((flags & NBUS_FLAG_NOREPLY) == 0);
}

int nb_do_egress(nbus_context_t *ctx, uint64_t ms, const char *dst, nb__res_t *res, nb__qry_t *qry)
{
    int err;
    int sd;
    struct sockaddr_un r_addr;
    socklen_t r_alen;

    struct timeval tv;

    err = 0;
    /* Open and connect a socket to remote. */
    sd = -1;
    if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return errno;
    }
    nb__make_addr(&r_addr, &r_alen, dst);

    if (ms > 0) {
        tv.tv_sec  =  ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;

        if (setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) == -1) {
            err = errno;
            goto done;
        }
        if (setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval)) == -1) {
            err = errno;
            goto done;
        }
    }
    /* Also, connect. */
    if (connect(sd, (struct sockaddr *)&r_addr, r_alen) == -1) {
        err = errno;
        goto done;
    }

    /* Send query header. */
    if (send(sd, qry, sizeof(nb__qry_t), MSG_NOSIGNAL) == -1) {
        err = errno;
        goto done;
    }
    /* Then data if any. */
    if (ctx->egress.len) {
        if (send(sd, ctx->egress.data, ctx->egress.len, MSG_NOSIGNAL) == -1) {
            err = errno;
            goto done;
        }
    }

    /* If this was a RPC, then wait for reply too only if there's a reply handler. */
    if (nb__needs_reply(qry->flags)) {
        /* Read response header. */
        if (recv(sd, res, sizeof(nb__res_t), 0) == -1) {
            err = errno;
            goto done;
        }
        /* Receive the data too. */
        if (res->len > 0) {
            if ((err = nb__grow_sb(ctx->flags, &ctx->ingress,  res->len)) != 0) goto done;
            ctx->ingress.len = 0;
            if (recv(sd, ctx->ingress.data, res->len, 0) == -1) {
                err = errno;
                goto done;
            }
            else {
                ctx->ingress.len = res->len;
            }
        }
    }

    err = 0;
done:
    close(sd);
    return err;
}

int nb__loop_remotes(nbus_context_t *ctx, int is_res, const char *pfx, const char *re, nbus__io_cb_t cb, void *arg)
#ifdef NBUS_PREFIX_IS_PATH
{
    DIR *dir;
    struct dirent *e;
    int err;
    struct stat st;
    char path[512];

    err = 0;

    if ((dir = opendir(pfx)) == NULL) {
        return errno;
    }

    while ((e = readdir(dir)) != NULL) {
        /* Skip dot directories. */
        if (strcmp(e->d_name, "..") == 0 || strcmp(e->d_name, ".") == 0) {
            continue;
        }
        /* Skip us. */
        if (strcmp(e->d_name, ctx->name) == 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", pfx, e->d_name);
        stat(path, &st);
        if (S_ISSOCK(st.st_mode)) {
            if ((is_res && NB__IS_RESERVED_ID(e->d_name)) || (fnmatch(re, e->d_name, 0) == 0)) {
                cb(ctx, 0, path, NULL, arg);
            }
        }
        else if (S_ISDIR(st.st_mode)) {
            if ((err = nb__loop_remotes(ctx, is_res, path, re, cb, arg)) != 0) {
                break;
            }
        }
    }

    closedir(dir);
    return err;
}
#else
{
    FILE *f_unix;
    char line[256] = {0}, *start, *end, *p;
    int err;

    f_unix = NULL;
    err = 0;

    (void)pfx;

    if ((f_unix = fopen("/proc/net/unix", "r")) == NULL) {
        return errno;
    }

    /* Start looping around. */
    fgets(line, sizeof(line), f_unix); /* Skip first line. */
    while (fgets(line, sizeof(line), f_unix) != NULL) {
        start = strstr(line, NBUS_CTX_NAME_PREFIX);
        if (start) {
            end = strchr(start, '\n');
            if (end) *end = 0;
            end = strchr(start, '@');
            if (end) *end = 0;

            p = start + sizeof(NBUS_CTX_NAME_PREFIX) - 1;

            /* If it's us, don't use it. */
            if (strcmp(ctx->name, p) == 0) {
                continue;
            }

            if ((is_res && NB__IS_RESERVED_ID(p)) || (fnmatch(re, p, 0) == 0)) {
                /* Matched? */
                if ((err = cb(ctx, 0, p, NULL, arg)) != 0) {
                    goto done;
                }
            }
        }
    }

done:
    if (f_unix) fclose(f_unix);

    return err;
}
#endif

int nb__init(nbus_context_t **r_ctx, int is_res, const char *name, const nbus_cb_reg_t *regs, void *buf, size_t *buf_len)
{
    const nbus_cb_reg_t *p;
    size_t n_regs;
    nbus_context_t ctx;
    int r;
    size_t so_len;
    struct sockaddr_un addr;
    socklen_t a_len;

    /* Important things first. */
    if (r_ctx) {
        *r_ctx = NULL;
    }

    if (!r_ctx || !name || (!buf && buf_len) || (buf && !buf_len)) {
        if (buf_len) {
            size_t n;

            n = NB__CTX_LEN;
            if (*buf_len) {
                n += nb__align_up((*buf_len)) * 2;
            }
            else {
                if ((so_len = nb__get_so_buflen(-1)) > 0) {
                    n += nb__align_up(so_len * 2);
                }
                else {
                    n += 8192;
                }
            }
            *buf_len = n;
        }
        return EINVAL;
    }

    if (!nb__is_valid_name(name, 1)) {
        return EINVAL;
    }

    if (buf_len && (*buf_len < NB__CTX_LEN)) {
        return ENOBUFS;
    }

    if (!is_res && NB__IS_RESERVED_ID(name))    return EINVAL;
    if (strlen(name) > NBUS_CTX_ID_LEN - 1)     return EINVAL;

    for (p = regs, n_regs = 0; p && p->flags != 0; p++, n_regs++) {
        if ((p->flags & NBUS_KIND_METHOD) != 0 && !nb__is_valid_name(p->name, 0)) {
            return EINVAL;
        }
        if (p->cb == NULL) {
            return EINVAL;
        }
    }

    memset(&ctx, 0, sizeof(nbus_context_t));
    strncpy(ctx.name, name, NBUS_CTX_ID_LEN - 1);
    ctx.regs = regs;
    ctx.n_regs = n_regs;

    r = 0;

    if ((ctx.fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        r = errno;
        goto done;
    }
    /* Make it non-blocking. */
    fcntl(ctx.fd, F_SETFL, O_NONBLOCK);

    nb__make_addr(&addr, &a_len, name);
#ifdef NBUS_PREFIX_IS_PATH
    unlink(addr.sun_path);
#endif

    if (bind(ctx.fd, (struct sockaddr*)&addr, a_len) == -1) {
        r = errno;
        close(ctx.fd);
        goto done;
    }

    if (listen(ctx.fd, SOMAXCONN) == -1) {
        r = errno;
        close(ctx.fd);
        goto done;
    }

    if (buf_len == NULL) {
        nbus_context_t *ptr;

        /* If no pre-allocated region was given, allocate one and mark the context as dynamic. */
        ctx.flags = NBF_DYNAMIC;

        if ((so_len = nb__get_so_buflen(ctx.fd)) > 0) {
            if ((r = nb__grow_sb(ctx.flags, &ctx.ingress, so_len)) != 0) goto done;
            if ((r = nb__grow_sb(ctx.flags, &ctx.egress,  so_len)) != 0) goto done;
        }

        r = ENOMEM;
        if ((ptr = calloc(1, NB__CTX_LEN)) != NULL) {
            memcpy(ptr, &ctx, sizeof(nbus_context_t));
            *r_ctx = ptr;
            r = 0;
        }
    }
    else {
        nbus_context_t *ptr;
        uint8_t *b;
        size_t n;

        ctx.flags = NBF_FIXED;

        n  = *buf_len;
        n -= NB__CTX_LEN;
        n /= 2;

        ptr = (nbus_context_t *)buf;
        b = buf;
        b += NB__CTX_LEN;
        ctx.ingress.data = b;
        ctx.ingress.cap  = n;
        b += n;
        ctx.egress.data  = b;
        ctx.egress.cap   = n;

        memcpy(ptr, &ctx, sizeof(nbus_context_t));
        *r_ctx = ptr;
        r = 0;
    }

done:
    return r;
}

int nbus_init(nbus_context_t **r_ctx, const char *name, const nbus_cb_reg_t *regs, void *buf, size_t *buf_len)
{
    return nb__init(r_ctx, 0, name, regs, buf, buf_len);
}

int nbus_exit(nbus_context_t *ctx)
{
#ifdef NBUS_PREFIX_IS_PATH
    char path[256];
#endif

    if (!ctx) {
        return EINVAL;
    }

    close(ctx->fd);
#ifdef NBUS_PREFIX_IS_PATH
    /* Delete the file. */
    snprintf(path, sizeof(path), NBUS_CTX_NAME_PREFIX "%s", ctx->name);
    unlink(path);
#endif
    /* If context was allocated dynamically, free it. */
    if ((ctx->flags & NBF_DYNAMIC) != 0) {
        free(ctx->ingress.data);
        free(ctx->egress.data);
        free(ctx);
    }
    return 0;
}

int nbus_get_fd(nbus_context_t *ctx)
{
    return (ctx)? ctx->fd: -1;
}

int nbus_set_output(nbus_context_t *ctx, const void *data, size_t n)
{
    int err;

    if ((err = nb__grow_sb(ctx->flags, &ctx->egress, n)) != 0) {
        return err;
    }
    memmove(ctx->egress.data, data, n);
    ctx->egress.len = n;

    return 0;
}

int nbus_handle(nbus_context_t *ctx)
{
    int fd, r;
    nb__qry_t qry;
    nb__res_t res;
    const nbus_cb_reg_t *cb;

    while ((fd = accept(ctx->fd, NULL, NULL)) != -1) {
        /* Receive header first. */
        if (recv(fd, &qry, sizeof(nb__qry_t), 0) == -1) {
            /* TODO Oops. What do now? */
            close(fd);
            continue;
        }

        if ((r = nb__grow_sb(ctx->flags, &ctx->ingress, qry.len + 1)) != 0) {
            close(fd);
            return r;
        }

        /* Also receive arguments if present. */
        if (qry.len) {
            if (recv(fd, ctx->ingress.data, qry.len, 0) == -1) {
                /* TODO - I/O error is not fatal? */
                close(fd);
                continue;
            }
        }
        ctx->ingress.data[qry.len] = 0;

        if ((qry.flags & NBUS_KIND_METHOD) != 0) {
            res.flags = NBUS_FLAG_CALL_BAD;

            ctx->egress.len = 0;
            if ((cb = nb__find_func(ctx, qry.name, qry.flags)) != NULL) {
                res.err   = cb->cb(ctx, NB_PROTO_ID(qry.flags), qry.id, qry.name, ctx->ingress.data, qry.len);
                res.flags = NBUS_FLAG_CALL_OK;
                res.len   = ctx->egress.len; /* Not the capacity. */
            }

                        /* First write the header. */
            if (send(fd, &res, sizeof(nb__res_t), MSG_NOSIGNAL) == -1) {
                if (errno == EPIPE) goto next;
                r = errno;
                close(fd);
                goto done;
            }
            /* The if there's data, send it too. */
            if (ctx->egress.len && (res.flags & NBUS_FLAG_NOREPLY) == 0) {
                if (send(fd, ctx->egress.data, ctx->egress.len, MSG_NOSIGNAL) == -1) {
                    if (errno == EPIPE) goto next;
                    r = errno;
                    close(fd);
                    goto done;
                }
            }
        }
        else if ((qry.flags & NBUS_KIND_EVENT) != 0) {
            if ((cb = nb__find_event(ctx, qry.name, qry.flags)) != NULL) {
                cb->cb(ctx, NB_PROTO_ID(qry.flags), qry.id, qry.name, ctx->ingress.data, qry.len);
            }
        }
        else if ((qry.flags & NBUS_FLAG_META) != 0) {
            res.flags = qry.flags;
            res.err = 0;
            res.len = (ctx->n_regs)? sizeof(nbus_cb_reg_t) * ctx->n_regs: 0;

            /* First write the header. */
            if (send(fd, &res, sizeof(nb__res_t), MSG_NOSIGNAL) == -1) {
                if (errno == EPIPE) goto next;
                r = errno;
                close(fd);
                goto done;
            }
            /* If there are any registrations to send out, send it. */
            if (res.len) {
                if (send(fd, ctx->regs, res.len, MSG_NOSIGNAL) == -1) {
                    if (errno == EPIPE) goto next;
                    r = errno;
                    close(fd);
                    goto done;
                }
            }
        }
    next:
        close(fd);
    }
    r = 0;

done:
    return r;
}

int nbus_invoke(
    nbus_context_t *ctx,
    uint64_t timeout,
    uint8_t proto,
    const char *dst,
    const char *method,
    const void *arg,
    size_t arg_len,
    nbus_reply_handler_t cb,
    void *extra
)
{
    int err;
    nb__qry_t qry;
    nb__res_t rep;

    memset(&qry, 0, sizeof(nb__qry_t));
    memset(&rep, 0, sizeof(nb__res_t));

    strncpy(qry.name, method, sizeof(qry.name) - 1);
    strncpy(qry.id, ctx->name, NBUS_CTX_ID_LEN);

    if (!ctx || !dst || !method) {
        return EINVAL;
    }
    if (strlen(dst) > NBUS_CTX_ID_LEN || strlen(method) > NBUS_NAME_LEN) {
        return EINVAL;
    }
    /* Cannot invoke on self. */
    if (strcmp(dst, ctx->name) == 0) {
        return EINVAL;
    }
    if ((err = nb__grow_sb(ctx->flags, &ctx->egress, arg_len)) != 0) {
        return err;
    }
    if (arg && arg_len) {
        memmove(ctx->egress.data, arg, arg_len);
        qry.len = ctx->egress.len = arg_len;
    }

    qry.flags = NBUS_KIND_METHOD | proto;
    if (cb == NULL) {
        qry.flags |= NBUS_FLAG_NOREPLY;
    }

    if ((err = nb_do_egress(ctx, timeout, dst, &rep, &qry)) != 0) {
        return err;
    }

    err = 0;
    if (cb) {
        if (rep.flags == NBUS_FLAG_CALL_OK) {
            cb(proto, rep.err, extra, (void *)ctx->ingress.data, ctx->ingress.len);
        }
        else {
            err = ENOMSG;
        }
    }

    return err;
}

int nbus_raise_event(
    nbus_context_t *ctx,
    uint8_t proto,
    const char *dst_wc,
    const char *name,
    const void *data,
    size_t n
)
{
    int err;
    nb__qry_t qry;

    memset(&qry, 0, sizeof(nb__qry_t));

    if (!ctx || !dst_wc || !name || (!data && n) || (data && !n)) {
        return EINVAL;
    }
    if (!nb__is_valid_name(name, 0)) return EINVAL;
    if (data && n) {
        if ((err = nb__grow_sb(ctx->flags, &ctx->egress,  n)) != 0) {
            return err;
        }
        memmove(ctx->egress.data, data, n);
        ctx->egress.len = n;
    }
    snprintf(qry.name, sizeof(qry.name), "%s", name);
    snprintf(qry.id, sizeof(qry.id), "%s", ctx->name);

    qry.flags = NBUS_KIND_EVENT | proto;
    qry.len = n;

    return nb__loop_remotes(ctx, 1, NBUS_CTX_NAME_PREFIX, dst_wc, nb_do_egress, &qry);
}
