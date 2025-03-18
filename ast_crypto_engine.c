/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

/* #define AFALG_NO_FALLBACK */
/* #define AFALG_ZERO_COPY */

#ifdef AFALG_ZERO_COPY
/* Required for vmsplice */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/uio.h>

static size_t zc_maxsize, pagemask;
#endif /* AFALG_ZERO_COPY */

#include <asm/byteorder.h>
#include <asm/types.h>
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef AFALG_NO_CRYPTOUSER
#include <linux/cryptouser.h>
#elif !defined(CRYPTO_MAX_NAME)
#define CRYPTO_MAX_NAME 64
#endif
#include <linux/if_alg.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include <linux/aio_abi.h>
#include "ast_crypto_engine.h"

/* linux/crypto.h is not public, so we must define the type and masks here,
 * and hope they are still valid. */
#ifndef CRYPTO_ALG_TYPE_MASK
#define CRYPTO_ALG_TYPE_MASK            0x0000000f
#define CRYPTO_ALG_TYPE_BLKCIPHER       0x00000004
#define CRYPTO_ALG_TYPE_SKCIPHER        0x00000005
#define CRYPTO_ALG_TYPE_AKCIPHER        0x00000006
#define CRYPTO_ALG_TYPE_SHASH           0x0000000e
#define CRYPTO_ALG_TYPE_AHASH           0x0000000f
#define CRYPTO_ALG_KERN_DRIVER_ONLY     0x00001000
#define CRYPTO_ALG_INTERNAL             0x00002000
#endif

#ifndef OSSL_NELEM
#define OSSL_NELEM(x)                   (sizeof(x)/sizeof((x)[0]))
#endif

/* SHA3_BLOCKSIZE is not exported, so we copy the definition here */
#ifndef SHA3_BLOCKSIZE
#define KECCAK1600_WIDTH 1600
#define SHA3_BLOCKSIZE(bitlen) (KECCAK1600_WIDTH - bitlen * 2) / 8
#endif

#define engine_afalg_id "ast_crypto_engine"

#define AFALG_REQUIRE_ACCELERATED 0 /* require confirmation of acceleration */
#define AFALG_USE_SOFTWARE        1 /* allow software drivers */
#define AFALG_REJECT_SOFTWARE     2 /* only disallow confirmed software drivers */

#define AFALG_DEFAULT_USE_SOFTDRIVERS   AFALG_USE_SOFTWARE

#ifndef AFALG_DEFAULT_USE_SOFTDRIVERS
#define AFALG_DEFAULT_USE_SOFTDRIVERS AFALG_REJECT_SOFTWARE
#endif
static int use_softdrivers = AFALG_DEFAULT_USE_SOFTDRIVERS;

/*
 * cipher/digest status & acceleration definitions
 * Make sure the defaults are set to 0
 */

struct driver_info_st {
    enum afalg_status_t {
        AFALG_STATUS_FAILURE       = -3, /* unusable for other reason */
        AFALG_STATUS_NO_COPY       = -2, /* hash state copy not supported */
        AFALG_STATUS_NO_OPEN       = -1, /* bind call failed */
        AFALG_STATUS_UNKNOWN       =  0, /* not tested yet */
        AFALG_STATUS_USABLE        =  1  /* algo can be used */
    } status;

    enum afalg_accelerated_t {
        AFALG_NOT_ACCELERATED      = -1, /* software implemented */
        AFALG_ACCELERATION_UNKNOWN =  0, /* acceleration support unkown */
        AFALG_ACCELERATED          =  1  /* hardware accelerated */
    } accelerated;
};

void engine_load_afalg_int(void);
void engine_load_afalg_int(void)
{
}

static int get_afalg_socket(const char *salg_name, const char *salg_type,
                            const __u32 feat, const __u32 mask)
{
    struct sockaddr_alg sa;
    int fd = -1;

    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    OPENSSL_strlcpy((char *)sa.salg_type, salg_type, sizeof(sa.salg_type));
    OPENSSL_strlcpy((char *)sa.salg_name, salg_name, sizeof(sa.salg_name));
    sa.salg_feat = feat;
    sa.salg_mask = mask;

    if ((fd = socket(AF_ALG, SOCK_SEQPACKET, 0)) < 0) {
        SYSerr(SYS_F_SOCKET, errno);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0)
        return fd;

    close(fd);
    return -1;
}

static int afalg_closefd(int fd)
{
    int ret;

    if (fd < 0 || (ret = close(fd)) == 0)
        return 0;

/* For compatibility with openssl 1.1.0 */
#ifdef SYS_F_CLOSE
    SYSerr(SYS_F_CLOSE, errno);
#endif

    return ret;
}

static int max_sendbuf_size = 0;
static int set_sendbuf_size(int fd)
{
    int ret = -1, snd_len, rlen;
    socklen_t optlen = sizeof(snd_len);
    FILE *fp;
    char buf[32], *end;

    memset(buf, 0, sizeof(buf));
    fp = fopen("/proc/sys/net/core/wmem_max", "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open /proc/sys/net/core/wmem_max\n");
        return ret;
    }
    rlen = fread(buf, 1, sizeof(buf)-1, fp);
    fclose(fp);
    if (rlen <= 0) {
        fprintf(stderr, "Failed to read /proc/sys/net/core/wmem_max\n");
        return ret;
    }

    snd_len = strtol(buf, &end, 10);
    if ((errno == ERANGE && (snd_len == LONG_MAX || snd_len == LONG_MIN))
        || (errno != 0 && snd_len == 0)) {
        fprintf(stderr, "Invalid wmem_max value (%s)\n", buf);
        return ret;
    }

    /* max send buffer size is twice wmem_max */
    snd_len *= 2;
    ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd_len, optlen);
    if (ret) {
        fprintf(stderr, "setsockopt is failed, errno = %d\n", errno);
        return ret;
    }

    max_sendbuf_size = snd_len;
    return 0;
}

struct afalg_alg_info {
    char alg_name[CRYPTO_MAX_NAME];
    char driver_name[CRYPTO_MAX_NAME];
    __u32 priority;
    __u32 flags;
};

static struct afalg_alg_info *afalg_alg_list = NULL;
static int afalg_alg_list_count = -1; /* no info available */

#ifndef AFALG_NO_CRYPTOUSER
static int prepare_afalg_alg_list(void)
{
    int ret = -EFAULT;

    /* NETLINK_CRYPTO specific */
    void *buf = NULL;
    struct nlmsghdr *res_n;
    int buf_size;
    struct {
        struct nlmsghdr n;
        struct crypto_user_alg cru;
    } req;

    struct crypto_user_alg *cru_res = NULL;
    struct afalg_alg_info *list;

    /* AF_NETLINK specific */
    struct sockaddr_nl nl;
    struct iovec iov;
    struct msghdr msg;
    struct rtattr *rta;
    int nlfd, msg_len, rta_len, list_count;
    __u32 alg_type;

    memset(&req, 0, sizeof(req));
    memset(&msg, 0, sizeof(msg));
    list = afalg_alg_list = NULL;
    afalg_alg_list_count = -1;

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.cru));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    req.n.nlmsg_type = CRYPTO_MSG_GETALG;

    /* open netlink socket */
    nlfd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
    if (nlfd < 0) {
        if (errno != EPROTONOSUPPORT) /* crypto_user module not available */
            printf("Netlink error: cannot open netlink socket");
        return -errno;
    }

    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    if (bind(nlfd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
        printf("Netlink error: cannot bind netlink socket");
        ret = -errno;
        goto out;
    }

    /* sending data */
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    iov.iov_base = (void*) &req.n;
    iov.iov_len = req.n.nlmsg_len;
    msg.msg_name = &nl;
    msg.msg_namelen = sizeof(nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (sendmsg(nlfd, &msg, 0) < 0) {
        printf("Netlink error: sendmsg failed");
        ret = -errno;
        goto out;
    }

    /* get the msg size */
    iov.iov_base = NULL;
    iov.iov_len = 0;
    buf_size = recvmsg(nlfd, &msg, MSG_PEEK | MSG_TRUNC);
    if (buf_size <= 0) {
        printf("Failed to get afalg_alg_list size\n");
        ret = -errno;
        goto out;
    }
    buf = OPENSSL_zalloc(buf_size);
    if (buf == NULL) {
        printf("Failed to get allocate memory: %d\n", buf_size);
        ret = -errno;
        goto out;
    }
    iov.iov_base = buf;
    iov.iov_len = buf_size;

    while (1) {
        if ((msg_len = recvmsg(nlfd, &msg, 0)) <= 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            if (msg_len == 0)
                printf("Nelink error: no data");
            else
                printf("Nelink error: netlink receive error");
            ret = -errno;
            goto out;
        }

        if ((u_int32_t)msg_len > buf_size) {
            printf("Netlink error: received too much data");
            ret = -errno;
            goto out;
        }

        break;
    }

    ret = -EFAULT;
    list_count = 0;
    for (res_n = (struct nlmsghdr *)buf; (ret = NLMSG_OK(res_n, (__u32)msg_len));
         res_n = NLMSG_NEXT(res_n, msg_len)) {
        if (res_n->nlmsg_type == NLMSG_ERROR) {
            ret = 0;
            goto out;
        }

        cru_res = NLMSG_DATA(res_n);
        if (res_n->nlmsg_type != CRYPTO_MSG_GETALG
            || !cru_res || res_n->nlmsg_len < NLMSG_SPACE(sizeof(*cru_res)))
            continue;

        alg_type = cru_res->cru_flags & CRYPTO_ALG_TYPE_MASK;
        if ((alg_type != CRYPTO_ALG_TYPE_SKCIPHER && alg_type != CRYPTO_ALG_TYPE_BLKCIPHER
             && alg_type != CRYPTO_ALG_TYPE_SHASH && alg_type != CRYPTO_ALG_TYPE_AHASH
             && alg_type != CRYPTO_ALG_TYPE_AKCIPHER)
            || cru_res->cru_flags & CRYPTO_ALG_INTERNAL)
            continue;

        list = OPENSSL_realloc(afalg_alg_list, (list_count + 1) * sizeof(struct afalg_alg_info));
        if (list == NULL) {
            OPENSSL_free(afalg_alg_list);
            afalg_alg_list = NULL;
            ret = -ENOMEM;
            goto out;
        }

        memset(&list[list_count], 0, sizeof(struct afalg_alg_info));
        afalg_alg_list = list;

        rta_len=msg_len;
        list[list_count].priority = 0;
        for (rta = (struct rtattr *)(((char *) cru_res)
                                     + NLMSG_ALIGN(sizeof(struct crypto_user_alg)));
             (ret = RTA_OK (rta, rta_len)); rta = RTA_NEXT(rta, rta_len)) {
            if (rta->rta_type == CRYPTOCFGA_PRIORITY_VAL) {
                list[list_count].priority = *((__u32 *)RTA_DATA(rta));
                break;
            }
        }

        OPENSSL_strlcpy(list[list_count].alg_name, cru_res->cru_name,
                        sizeof(list->alg_name));
        OPENSSL_strlcpy(list[list_count].driver_name, cru_res->cru_driver_name,
                        sizeof(list->driver_name));
        list[list_count].flags = cru_res->cru_flags;
        list_count++;
    }
    ret = afalg_alg_list_count = list_count;
out:
    close(nlfd);
    OPENSSL_free(buf);
    return ret;
}
#endif

#ifndef AFALG_NO_CRYPTOUSER
static const char *
afalg_get_driver_name(const char *alg_name,
                      enum afalg_accelerated_t expected_accel)
{
    int i;
    __u32 priority = 0;
    int found = 0;
    enum afalg_accelerated_t accel;
    const char *driver_name = "unknown";

    for (i = 0; i < afalg_alg_list_count; i++) {
        if (strcmp(afalg_alg_list[i].alg_name, alg_name) ||
            priority > afalg_alg_list[i].priority)
            continue;

        if (afalg_alg_list[i].flags & CRYPTO_ALG_KERN_DRIVER_ONLY)
            accel = AFALG_ACCELERATED;
        else
            accel = AFALG_NOT_ACCELERATED;

        if ((found && priority == afalg_alg_list[i].priority)
            || accel != expected_accel) {
            driver_name = "**unreliable info**";

        } else {
            found = 1;
            priority = afalg_alg_list[i].priority;
            driver_name = afalg_alg_list[i].driver_name;
        }
    }

    return driver_name;
}
#endif

/******************************************************************************
 *
 * Ciphers
 *
 *****************************************************************************/

struct cipher_data_st {
    int nid;
    int blocksize;
    int keylen;
    int ivlen;
    int flags;
    const char *name;
#ifndef AFALG_NO_FALLBACK
    const EVP_CIPHER *((*fallback) (void));
    int fb_threshold;
#endif
};

struct cipher_ctx {
    int bfd, sfd;
#ifdef AFALG_ZERO_COPY
    int pipes[2];
#endif
#ifndef AFALG_NO_FALLBACK
    EVP_CIPHER_CTX *fallback;
    int fb_threshold;
#endif
    int control_is_set;
    const struct cipher_data_st *cipher_d;
    unsigned int blocksize, num;
    unsigned char partial[EVP_MAX_BLOCK_LENGTH];
};

#ifndef OPENSSL_NO_DES
#define OPENSSL_NO_DES
#endif

static const struct cipher_data_st cipher_data[] = {
#ifndef OPENSSL_NO_DES
    { NID_des_cbc, 8, 8, 8, EVP_CIPH_CBC_MODE, "cbc(des)",
#ifndef AFALG_NO_FALLBACK
      EVP_des_cbc, 320
#endif
    },
    { NID_des_ede3_cbc, 8, 24, 8, EVP_CIPH_CBC_MODE, "cbc(des3_ede)",
#ifndef AFALG_NO_FALLBACK
      EVP_des_ede3_cbc, 96
#endif
    },
#endif
    { NID_aes_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_cbc, 1536
#endif
    },
    { NID_aes_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_cbc, 1152
#endif
    },
    { NID_aes_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE, "cbc(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_cbc, 960
#endif
    },
    { NID_aes_128_ctr, 16, 128 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_ctr, 1360
#endif
    },
    { NID_aes_192_ctr, 16, 192 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_ctr, 1152
#endif
    },
    { NID_aes_256_ctr, 16, 256 / 8, 16, EVP_CIPH_CTR_MODE, "ctr(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_ctr, 960
#endif
    },
    { NID_aes_128_ecb, 16, 128 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_ecb, 2048
#endif
    },
    { NID_aes_192_ecb, 16, 192 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_ecb, 1440
#endif
    },
    { NID_aes_256_ecb, 16, 256 / 8, 0, EVP_CIPH_ECB_MODE, "ecb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_ecb, 1152
#endif
    },
    { NID_aes_128_cfb128, 16, 128 / 8, 16, EVP_CIPH_CFB_MODE, "cfb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_cfb, 2048
#endif
    },
    { NID_aes_192_cfb128, 16, 192 / 8, 16, EVP_CIPH_CFB_MODE, "cfb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_cfb, 1440
#endif
    },
    { NID_aes_256_cfb128, 16, 256 / 8, 16, EVP_CIPH_CFB_MODE, "cfb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_cfb, 1152
#endif
    },
    { NID_aes_128_ofb128, 16, 128 / 8, 16, EVP_CIPH_OFB_MODE, "ofb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_128_ofb, 2048
#endif
    },
    { NID_aes_192_ofb128, 16, 192 / 8, 16, EVP_CIPH_OFB_MODE, "ofb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_192_ofb, 1440
#endif
    },
    { NID_aes_256_ofb128, 16, 256 / 8, 16, EVP_CIPH_OFB_MODE, "ofb(aes)",
#ifndef AFALG_NO_FALLBACK
      EVP_aes_256_ofb, 1152
#endif
    },

};

static size_t find_cipher_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        if (nid == cipher_data[i].nid)
            return i;

    return (size_t)-1;
}

static size_t get_cipher_data_index(int nid)
{
    size_t i = find_cipher_data_index(nid);

    if (i != (size_t)-1)
        return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

static int afalg_set_key(int sfd, const void *key, int keylen, int sockopt)
{
    if (setsockopt(sfd, SOL_ALG, sockopt, key, keylen) >= 0)
        return 1;

    return 0;
}

static int afalg_set_control(struct msghdr *msg, int op,
                             const unsigned char *iv, unsigned int ivlen)
{
    size_t set_op_len = sizeof(op);
    size_t set_iv_len;
    struct cmsghdr *cmsg;
    struct af_alg_iv *aiv;

    if (!iv)
        ivlen = 0;

    set_iv_len = offsetof(struct af_alg_iv, iv) + ivlen;
    msg->msg_controllen = CMSG_SPACE(set_op_len)
                          + (ivlen > 0 ? CMSG_SPACE(set_iv_len) : 0);
    msg->msg_control = OPENSSL_zalloc(msg->msg_controllen);
    if (msg->msg_control == NULL) {
        printf("afalg_set_control: OPENSSL_zalloc failed, %zu\n", msg->msg_controllen);
        return 0;
    }

    cmsg = CMSG_FIRSTHDR(msg);
    if (cmsg == NULL) {
        ALG_WARN("%s: CMSG_FIRSTHDR error setting op.\n", __func__);
        goto err;
    }

    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(op));
    *(CMSG_DATA(cmsg)) = op;
    if (ivlen == 0)
        return 1;

    cmsg = CMSG_NXTHDR(msg, cmsg);
    if (cmsg == NULL) {
        ALG_WARN("%s: CMSG_NXTHDR error setting iv.\n", __func__);
        goto err;
    }

    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + ivlen);
    aiv = (void *)CMSG_DATA(cmsg);
    aiv->ivlen = ivlen;
    memcpy(aiv->iv, iv, ivlen);

    return 1;

err:
    OPENSSL_free(msg->msg_control);
    msg->msg_control = NULL;
    msg->msg_controllen = 0;

    return 0;
}

#ifndef AFALG_NO_FALLBACK
static EVP_CIPHER_CTX *cipher_fb_ctx[OSSL_NELEM(cipher_data)][2] = { { NULL, }, };
static int cipher_fb_threshold[OSSL_NELEM(cipher_data)] = { 0, };

static int prepare_cipher_fallback(int i, int enc)
{
    int ret;

    cipher_fb_ctx[i][enc] = EVP_CIPHER_CTX_new();

    if (!cipher_fb_ctx[i][enc])
        return 0;

    if ((ret = EVP_CipherInit_ex2(cipher_fb_ctx[i][enc], cipher_data[i].fallback(),
                                  NULL, NULL, enc, NULL))) {
        return 1;
    }

    ALG_WARN("%s: cipher init error\n", __func__);
    EVP_CIPHER_CTX_free(cipher_fb_ctx[i][enc]);
    cipher_fb_ctx[i][enc] = NULL;

    return 0;
}

static int cipher_fb_init(struct cipher_ctx *cipher_ctx,
                          EVP_CIPHER_CTX *source_ctx,
                          const unsigned char *key,
                          const unsigned char *iv, int enc)
{
    /* Now we can set key and IV */
    if (!EVP_CipherInit_ex2(source_ctx, NULL, key, iv, enc, NULL)) {
            /* Error */
            ALG_WARN("%s: cipher_init() error\n", __func__);
            EVP_CIPHER_CTX_free(source_ctx);
            return 0;
    }

    return 1;
}
#endif

static int cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t i = get_cipher_data_index(EVP_CIPHER_CTX_nid(ctx));
    const struct cipher_data_st *cipher_d = &cipher_data[i];
    int mode = EVP_CIPHER_CTX_mode(ctx);
    __u32 afalg_mask;
    int keylen;

    if (cipher_ctx->bfd == -1) {
        if (mode == EVP_CIPH_CTR_MODE)
            cipher_ctx->blocksize = cipher_d->blocksize;

        if (use_softdrivers == AFALG_REQUIRE_ACCELERATED)
            afalg_mask = CRYPTO_ALG_KERN_DRIVER_ONLY;
        else
            afalg_mask = 0;

        cipher_ctx->bfd = get_afalg_socket(cipher_d->name, "skcipher",
                                           afalg_mask, afalg_mask);
        if (cipher_ctx->bfd < 0) {
            SYSerr(SYS_F_BIND, errno);
            return 0;
        }
    }

    if (cipher_ctx->sfd != -1) {
        close(cipher_ctx->sfd);
        cipher_ctx->sfd = -1;
    }

    if (key != NULL) {
        if ((keylen = EVP_CIPHER_CTX_key_length(ctx)) > 0
            && !afalg_set_key(cipher_ctx->bfd, key, keylen, ALG_SET_KEY)) {
            printf("cipher_init: Error setting key.\n");
            goto err;
        }
#ifndef AFALG_NO_FALLBACK
        if (cipher_fb_ctx[i][enc]) {
            if (!cipher_fb_init(cipher_ctx, cipher_fb_ctx[i][enc], key, iv,
                                enc)) {
                printf("cipher_init: Warning: Cannot set fallback key."
                                " Fallback will not be used!\n");
            } else {
                cipher_ctx->fb_threshold = cipher_fb_threshold[i];
            }
        }
#endif
    }

    if ((cipher_ctx->sfd = accept(cipher_ctx->bfd, NULL, 0)) < 0) {
        printf("cipher_init: accept");
        goto err;
    }

    if (set_sendbuf_size(cipher_ctx->sfd))
        goto err;

#ifdef AFALG_ZERO_COPY
    if (pipe(cipher_ctx->pipes) < 0) {
        printf("cipher_init: pipes");
        goto err;
    }
#endif
    cipher_ctx->cipher_d = cipher_d;
    return 1;

err:
    close(cipher_ctx->bfd);
    if (cipher_ctx->sfd >= 0) {
        close(cipher_ctx->sfd);
        cipher_ctx->sfd = -1;
    }
    return 0;
}

static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct msghdr msg = { 0 };
    struct iovec iov;
    int res = -1;
    int ret = 0;
    int op = EVP_CIPHER_CTX_encrypting(ctx) ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
    int ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
#ifndef AFALG_NO_FALLBACK
    const EVP_CIPHER *fb_cipher;
    int (*fb_do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t inl);
#endif

    if (ivlen < 0) {
        fprintf(stderr, "Get IV length failed.\n");
        return -1;
    }

    if (max_sendbuf_size < inl) {
        fprintf(stderr, "Input data size (%zu) is too big to send to Kernel driver.\n", inl);
        fprintf(stderr, "Please enlarge the wmem_max (/proc/sys/net/core/wmem_max) for further test\n");
        return -1;
    }
#ifndef AFALG_NO_FALLBACK
    if (inl < (size_t)cipher_ctx->fb_threshold) {
        ALG_DBG("%s: inl(%zu) < fb_threshold(%d), do_fb_cipher()\n",
                __func__, inl, cipher_ctx->fb_threshold);

        if ((fb_cipher = EVP_CIPHER_CTX_cipher(cipher_ctx->fallback))
            && (fb_do_cipher = EVP_CIPHER_meth_get_do_cipher(fb_cipher))) {
            if (ivlen) {
                memcpy(EVP_CIPHER_CTX_iv_noconst(cipher_ctx->fallback), iv, ivlen);
                cipher_ctx->control_is_set = 0;
            }
            return fb_do_cipher(cipher_ctx->fallback, out, in, inl);
        }
    }
#endif
    if (!cipher_ctx->control_is_set) {
        afalg_set_control(&msg, op, iv, ivlen);
        cipher_ctx->control_is_set = 1;
    }

    iov.iov_base = (void *)in;
    iov.iov_len = inl;

#ifdef AFALG_ZERO_COPY
    if (inl <= zc_maxsize && ((size_t)in & pagemask) == 0) {
        if (msg.msg_control && sendmsg(cipher_ctx->sfd, &msg, 0) < 0) {
            printf ("afalg_do_cipher: sendmsg");
            goto out;
        }
        res = vmsplice(cipher_ctx->pipes[1], &iov, 1,
                       SPLICE_F_GIFT & SPLICE_F_MORE);
        if (res < 0) {
            printf("afalg_do_cipher: vmsplice");
            goto out;
        } else if (res != (ssize_t) inl) {
            fprintf(stderr,
                    "afalg_do_cipher: vmsplice: sent %zd bytes != len %zd\n",
                    res, inl);
            goto out;
        }
        res = splice(cipher_ctx->pipes[0], NULL, cipher_ctx->sfd, NULL, inl, 0);
        if (res < 0) {
            printf("afalg_do_cipher: splice");
            goto out;
        } else if (res != (ssize_t) inl) {
            fprintf(stderr,
                    "afalg_do_cipher: splice: spliced %zd bytes != len %zd\n",
                    res, inl);
            goto out;
        }
    } else
#endif
    {
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        if ((res = sendmsg(cipher_ctx->sfd, &msg, 0)) < 0) {
            printf("afalg_do_cipher: sendmsg");
            goto out;
        } else if (res != (size_t) inl) {
            ALG_ERR("afalg_do_cipher: sent 0x%x bytes != len 0x%x\n",
                    (__u32)res, (__u32)inl);
            goto out;
        }
    }

    if ((res = read(cipher_ctx->sfd, out, inl)) == (size_t) inl)
        ret = 1;
    else
        ALG_ERR("afalg_do_cipher: read 0x%x bytes != len 0x%x\n",
                (__u32)res, (__u32)inl);

out:
    if (msg.msg_control)
        OPENSSL_free(msg.msg_control);

    return ret;
}

static int cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
#ifndef AFALG_NO_FALLBACK
    int enc = EVP_CIPHER_CTX_encrypting(ctx);
    int ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
    unsigned char saved_iv[EVP_MAX_IV_LENGTH];
    int ret;

    if (ivlen < 0) {
        fprintf(stderr, "Get IV length failed.\n");
        return -1;
    }

    assert(inl >= ivlen);
    if (!enc)
        memcpy(saved_iv, in + inl - ivlen, ivlen);
    if ((ret = afalg_do_cipher(ctx, out, in, inl)))
        memcpy(iv, enc ? out + inl - ivlen : saved_iv, ivlen);
    return ret;
#else
    return afalg_do_cipher(ctx, out, in, inl);
#endif
}

#if !defined(AFALG_KERNEL_UPDATES_CTR_IV) || !defined(AFALG_NO_FALLBACK)
static void ctr_update_iv(unsigned char *iv, size_t ivlen, __u64 nblocks)
{
    __be64 *a = (__be64 *)(iv + ivlen);
    __u64 b;

    for (; ivlen >= 8; ivlen -= 8) {
        b = nblocks + __be64_to_cpu(*--a);
        *a = __cpu_to_be64(b);
        if (nblocks < b)
            return;
        nblocks = 1;
    }
}
#endif

static int ctr_do_blocks(EVP_CIPHER_CTX *ctx, struct cipher_ctx *cipher_ctx,
                         unsigned char *out, const unsigned char *in,
                         size_t inl, size_t nblocks)
{
#if !defined(AFALG_KERNEL_UPDATES_CTR_IV) || !defined(AFALG_NO_FALLBACK)
    int ret;
    int ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);

    if (ivlen < 0) {
        fprintf(stderr, "Get IV length failed.\n");
        return -1;
    }

    ret = afalg_do_cipher(ctx, out, in, inl);
    if (ret) {
        if (cipher_ctx->control_is_set) {
            ctr_update_iv(iv, ivlen, nblocks);
# ifndef AFALG_KERNEL_UPDATES_CTR_IV
            cipher_ctx->control_is_set = 0;
# endif
        } else {
# ifndef AFALG_NO_FALLBACK
            memcpy(iv, EVP_CIPHER_CTX_iv(cipher_ctx->fallback), ivlen);
# endif
        }
    }
    return ret;
#else
    (void)cipher_ctx;
    (void)nblocks;
    return afalg_do_cipher(ctx, out, in, inl);
#endif
}

static int ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t nblocks, len;

    /* handle initial partial block */
    while (cipher_ctx->num && inl) {
        (*out++) = *(in++) ^ cipher_ctx->partial[cipher_ctx->num];
        --inl;
        cipher_ctx->num = (cipher_ctx->num + 1) % cipher_ctx->blocksize;
    }

    /* process full blocks */
    if (inl >= (unsigned int) cipher_ctx->blocksize) {
        nblocks = inl / cipher_ctx->blocksize;
        len = nblocks * cipher_ctx->blocksize;
        if (!ctr_do_blocks(ctx, cipher_ctx, out, in, len, nblocks))
            return 0;
        inl -= len;
        out += len;
        in += len;
    }

    /* process final partial block */
    if (inl) {
        memset(cipher_ctx->partial, 0, cipher_ctx->blocksize);
        if (!ctr_do_blocks(ctx, cipher_ctx, cipher_ctx->partial,
                             cipher_ctx->partial, cipher_ctx->blocksize, 1))
            return 0;
        while (inl--) {
            out[cipher_ctx->num] = in[cipher_ctx->num]
                ^ cipher_ctx->partial[cipher_ctx->num];
            cipher_ctx->num++;
        }
    }

    return 1;
}

static int cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int p1, void* p2)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct cipher_ctx *to_cipher_ctx;

    (void)p1;
    switch (type) {

    case EVP_CTRL_COPY:
        if (cipher_ctx == NULL)
            return 1;
        /* when copying the context, a new session needs to be initialized */
        to_cipher_ctx = (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(
                        (EVP_CIPHER_CTX *)p2);

        to_cipher_ctx->bfd = to_cipher_ctx->sfd = -1;
        to_cipher_ctx->control_is_set = 0;
#ifdef AFALG_ZERO_COPY
        if (pipe(to_cipher_ctx->pipes) != 0)
            return 0;
#endif
#ifndef AFALG_NO_FALLBACK
        if (cipher_ctx->fallback) {
            if (!(to_cipher_ctx->fallback = EVP_CIPHER_CTX_new()))
                return 0;
            if (!EVP_CIPHER_CTX_copy(to_cipher_ctx->fallback,
                                     cipher_ctx->fallback)) {
                EVP_CIPHER_CTX_free(to_cipher_ctx->fallback);
                to_cipher_ctx->fallback = NULL;
                return 0;
            }
        }
#endif
        if ((to_cipher_ctx->bfd = dup(cipher_ctx->bfd)) == -1) {
            ALG_WARN("%s\n", __func__);
            return 0;
        }
        if ((to_cipher_ctx->sfd = accept(to_cipher_ctx->bfd, NULL, 0)) != -1)
            return 1;
        SYSerr(SYS_F_ACCEPT, errno);
#ifdef AFALG_ZERO_COPY
        close(to_cipher_ctx->pipes[0]);
        close(to_cipher_ctx->pipes[1]);
#endif
        return 0;

    case EVP_CTRL_INIT:
        cipher_ctx->bfd = cipher_ctx->sfd = -1;
        return 1;

    default:
        break;
    }

    return -1;
}

static int cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    int ret;

    if (cipher_ctx == NULL)
        return 1;
#ifndef AFALG_NO_FALLBACK
    if (cipher_ctx->fallback) {
        EVP_CIPHER_CTX_free(cipher_ctx->fallback);
        cipher_ctx->fallback = NULL;
    }
#endif
    ret = !(0
#ifdef AFALG_ZERO_COPY
            | afalg_closefd(cipher_ctx->pipes[0])
            | afalg_closefd(cipher_ctx->pipes[1])
#endif
            | afalg_closefd(cipher_ctx->sfd)
            | afalg_closefd(cipher_ctx->bfd));

    cipher_ctx->bfd = cipher_ctx->sfd = -1;
    return ret;
}

/*
 * Keep tables of known nids, associated methods, selected ciphers, and driver
 * info.
 * Note that known_cipher_nids[] isn't necessarily indexed the same way as
 * cipher_data[] above, which the other tables are.
 */
static int known_cipher_nids[OSSL_NELEM(cipher_data)];
static int known_cipher_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_CIPHER *known_cipher_methods[OSSL_NELEM(cipher_data)] = { NULL, };
static int selected_ciphers[OSSL_NELEM(cipher_data)];
static struct driver_info_st cipher_driver_info[OSSL_NELEM(cipher_data)];

static int afalg_test_cipher(size_t cipher_data_index)
{
    return (cipher_driver_info[cipher_data_index].status == AFALG_STATUS_USABLE
            && selected_ciphers[cipher_data_index] == 1
            && (cipher_driver_info[cipher_data_index].accelerated
                    == AFALG_ACCELERATED
                || use_softdrivers == AFALG_USE_SOFTWARE
                || (cipher_driver_info[cipher_data_index].accelerated
                        != AFALG_NOT_ACCELERATED
                    && use_softdrivers == AFALG_REJECT_SOFTWARE)));
}

static void prepare_cipher_methods(void)
{
    int (*do_cipher) (EVP_CIPHER_CTX *, unsigned char *, const unsigned char *,
                      size_t);
    int fd, blocksize;
    size_t i;

    for (i = 0, known_cipher_nids_amount = 0;
         i < OSSL_NELEM(cipher_data); i++) {

        selected_ciphers[i] = 1;
        /*
         * Check that the cipher is usable
         */
        if ((fd =
            get_afalg_socket(cipher_data[i].name, "skcipher", 0, 0)) < 0) {
            cipher_driver_info[i].status = AFALG_STATUS_NO_OPEN;
            continue;
        }
        close(fd);

        /* test hardware acceleration */
        if ((fd =
            get_afalg_socket(cipher_data[i].name, "skcipher",
                             CRYPTO_ALG_KERN_DRIVER_ONLY,
                             CRYPTO_ALG_KERN_DRIVER_ONLY)) >= 0) {
            cipher_driver_info[i].accelerated = AFALG_ACCELERATED;
            close(fd);
        } else {
            cipher_driver_info[i].accelerated = AFALG_NOT_ACCELERATED;
        }

        blocksize = cipher_data[i].blocksize;
        switch (cipher_data[i].flags & EVP_CIPH_MODE) {
        case EVP_CIPH_CBC_MODE:
            do_cipher = cbc_do_cipher;
            break;
        case EVP_CIPH_CTR_MODE:
            do_cipher = ctr_do_cipher;
            blocksize = 1;
            break;
        case EVP_CIPH_ECB_MODE:
            do_cipher = afalg_do_cipher;
            break;
        case EVP_CIPH_CFB_MODE:
            do_cipher = afalg_do_cipher;
            blocksize = 1;
            break;
        case EVP_CIPH_OFB_MODE:
            do_cipher = afalg_do_cipher;
            blocksize = 1;
            break;
        default:
            cipher_driver_info[i].status = AFALG_STATUS_FAILURE;
            known_cipher_methods[i] = NULL;
            continue;
        }

        if ((known_cipher_methods[i] =
                 EVP_CIPHER_meth_new(cipher_data[i].nid, blocksize,
                                     cipher_data[i].keylen)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(known_cipher_methods[i],
                                              cipher_data[i].ivlen)
            || !EVP_CIPHER_meth_set_flags(known_cipher_methods[i],
                                          cipher_data[i].flags
                                          | EVP_CIPH_CUSTOM_COPY
                                          | EVP_CIPH_CTRL_INIT
                                          | EVP_CIPH_FLAG_DEFAULT_ASN1)
            || !EVP_CIPHER_meth_set_init(known_cipher_methods[i], cipher_init)
            || !EVP_CIPHER_meth_set_do_cipher(known_cipher_methods[i], do_cipher)
            || !EVP_CIPHER_meth_set_ctrl(known_cipher_methods[i], cipher_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(known_cipher_methods[i],
                                            cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(known_cipher_methods[i],
                                                  sizeof(struct cipher_ctx))) {
            cipher_driver_info[i].status = AFALG_STATUS_FAILURE;
            EVP_CIPHER_meth_free(known_cipher_methods[i]);
            known_cipher_methods[i] = NULL;
        } else {
#ifndef AFALG_NO_FALLBACK
            int ret;

            if (cipher_data[i].fallback) {
                ret = prepare_cipher_fallback(i, 0);
                if (!ret) {
                    ALG_DBG("prepare cipher fallback dec [%zu] failed\n", i);
                }

                ret = prepare_cipher_fallback(i, 1);
                if (!ret){
                    ALG_DBG("prepare cipher fallback enc [%zu] failed\n", i);
                }

                cipher_fb_threshold[i] = cipher_data[i].fb_threshold;
            }
#endif
            cipher_driver_info[i].status = AFALG_STATUS_USABLE;
            if (afalg_test_cipher(i))
                known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
        }
    }
}

static void rebuild_known_cipher_nids(ENGINE *e)
{
    size_t i;

    for (i = 0, known_cipher_nids_amount = 0; i < OSSL_NELEM(cipher_data); i++) {
        if (afalg_test_cipher(i))
            known_cipher_nids[known_cipher_nids_amount++] = cipher_data[i].nid;
    }
    ENGINE_unregister_ciphers(e);
    ENGINE_register_ciphers(e);
}

static const EVP_CIPHER *get_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    if (i == (size_t)-1)
        return NULL;

    return known_cipher_methods[i];
}

static int get_cipher_nids(const int **nids)
{
    *nids = known_cipher_nids;
    return known_cipher_nids_amount;
}

static void destroy_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    EVP_CIPHER_meth_free(known_cipher_methods[i]);
    known_cipher_methods[i] = NULL;
}

static void destroy_all_cipher_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        destroy_cipher_method(cipher_data[i].nid);
}

static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid)
{
    (void)e;
    if (cipher == NULL)
        return get_cipher_nids(nids);

    *cipher = get_cipher_method(nid);

    return *cipher != NULL;
}

static void afalg_select_all_ciphers(int *cipher_list, int include_ecb)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        if (include_ecb ||
           ((cipher_data[i].flags & EVP_CIPH_MODE) != EVP_CIPH_ECB_MODE))
            cipher_list[i] = 1;
        else
            cipher_list[i] = 0;
    }
}

static int afalg_select_cipher_cb(const char *str, int len, void *usr)
{
    int *cipher_list = (int *)usr;
    char *name, *fb;
    const EVP_CIPHER *EVP;
    size_t i;

    if (len == 0)
        return 1;

    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;

    /* Even thought it is useful only with fallback enabled, keep the check here
     * so that the same config file works with or without AFALG_NO_FALLBACK */
    if ((fb = index(name, ':'))) {
        *(fb) = '\0';
        fb++;
    }

    EVP = EVP_get_cipherbyname(name);
    if (EVP == NULL) {
        ALG_ERR("afalg: unknown cipher %s\n", name);
    } else if ((i = find_cipher_data_index(EVP_CIPHER_nid(EVP))) != (size_t)-1) {
        cipher_list[i] = 1;
#ifndef AFALG_NO_FALLBACK
        if (fb && (cipher_fb_threshold[i] = atoi(fb)) < 0) {
            cipher_fb_threshold[i] = cipher_data[i].fb_threshold;
        }
#endif
    } else {
        ALG_ERR("afalg: cipher %s not available\n", name);
    }

    OPENSSL_free(name);
    return 1;
}

static void dump_cipher_info(void)
{
    size_t i;
    const char *evp_name;
#ifndef AFALG_NO_CRYPTOUSER
    const char *driver_name;
#endif

    fprintf (stderr, "Information about ciphers supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(cipher_data); i++) {
        evp_name = OBJ_nid2sn(cipher_data[i].nid);
        fprintf (stderr, "Cipher %s, NID=%d, AF_ALG info: name=%s",
                 evp_name ? evp_name : "unknown", cipher_data[i].nid,
                 cipher_data[i].name);
        if (cipher_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, ". AF_ALG socket bind failed.\n");
            continue;
        }
#ifndef AFALG_NO_CRYPTOUSER
        /* gather hardware driver information */
        if (afalg_alg_list_count > 0) {
            driver_name =
                afalg_get_driver_name(cipher_data[i].name,
                                      cipher_driver_info[i].accelerated);
        } else {
            driver_name = "unknown";
        }
        ALG_ERR(", driver=%s", driver_name);
#endif
        if (cipher_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, " (hw accelerated)");
        else if (cipher_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            printf(" (software)");
        else
            printf(" (acceleration status unknown)");
#ifndef AFALG_NO_FALLBACK
        if (cipher_data[i].fallback) {
            ALG_ERR(", sw fallback available, default threshold=%d",
                    cipher_data[i].fb_threshold);
        }
#endif
        if (cipher_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Cipher setup failed.");
        fprintf (stderr, "\n");
    }
    printf("\n");
}

#ifndef AFALG_DIGESTS
#define AFALG_DIGESTS
#endif

#ifdef AFALG_DIGESTS
/******************************************************************************
 *
 * Digests
 *
 *****/

/* Cache up to this amount before sending the request to AF_ALG */
#ifndef AFALG_DIGEST_CACHE_SIZE
#define AFALG_DIGEST_CACHE_SIZE 16384
#endif

/* If the request is larger than this, send the current cache as is, then the
 * new request, instead of resizing the cache and sending it all at once
 */
#ifndef AFALG_DIGEST_CACHE_MAXSIZE
#define AFALG_DIGEST_CACHE_MAXSIZE 262144
#endif

struct digest_ctx {
    int bfd, sfd;
#ifdef AFALG_ZERO_COPY
    int pipes[2];
#endif
#ifndef AFALG_NO_FALLBACK
    const EVP_MD_CTX *fallback;
    int fb_threshold;
    unsigned char res[EVP_MAX_MD_SIZE];
#endif
    const struct digest_data_st *digest_d;
    size_t inp_len;
    void *inp_data;
};

static const struct digest_data_st {
    int nid;
    int blocksize;
    int digestlen;
    char *name;
#ifndef AFALG_NO_FALLBACK
    const EVP_MD *((*fallback) (void));
    int fb_threshold;
#endif
} digest_data[] = {
#ifndef OPENSSL_NO_MD5
    { NID_md5, /* MD5_CBLOCK */ 64, 16, "md5",
#ifndef AFALG_NO_FALLBACK
      EVP_md5, 16384
#endif
    },
#endif
    { NID_sha1, SHA_CBLOCK, 20, "sha1",
#ifndef AFALG_NO_FALLBACK
      EVP_sha1, 16384
#endif
    },
    { NID_sha224, SHA256_CBLOCK, 224 / 8, "sha224",
#ifndef AFALG_NO_FALLBACK
      EVP_sha224, 16384
#endif
    },
    { NID_sha256, SHA256_CBLOCK, 256 / 8, "sha256",
#ifndef AFALG_NO_FALLBACK
      EVP_sha256, 16384
#endif
    },
    { NID_sha384, SHA512_CBLOCK, 384 / 8, "sha384",
#ifndef AFALG_NO_FALLBACK
      EVP_sha384, 16384
#endif
    },
    { NID_sha512, SHA512_CBLOCK, 512 / 8, "sha512",
#ifndef AFALG_NO_FALLBACK
      EVP_sha512, 16384
#endif
    },
    { NID_sha3_224, SHA3_BLOCKSIZE(224), 224 / 8, "sha3-224",
#ifndef AFALG_NO_FALLBACK
      EVP_sha224, 16384
#endif
    },
    { NID_sha3_256, SHA3_BLOCKSIZE(256), 256 / 8, "sha3-256",
#ifndef AFALG_NO_FALLBACK
      EVP_sha256, 16384
#endif
    },
    { NID_sha3_384, SHA3_BLOCKSIZE(384), 384 / 8, "sha3-384",
#ifndef AFALG_NO_FALLBACK
      EVP_sha384, 16384
#endif
    },
    { NID_sha3_512, SHA3_BLOCKSIZE(512), 512 / 8, "sha3-512",
#ifndef AFALG_NO_FALLBACK
      EVP_sha512, 16384
#endif
    },

};

static size_t find_digest_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        if (nid == digest_data[i].nid)
            return i;

    return (size_t)-1;
}

static size_t get_digest_data_index(int nid)
{
    size_t i = find_digest_data_index(nid);

    if (i != (size_t)-1)
        return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

#ifndef AFALG_NO_FALLBACK
static EVP_MD_CTX *digest_fb_ctx[OSSL_NELEM(digest_data)] = { NULL, };
static int digest_fb_threshold[OSSL_NELEM(cipher_data)] = { 0, };

static int digest_use_fb(const EVP_MD_CTX *fallback, const void *data,
                         size_t len, unsigned char *res)
{
    EVP_MD_CTX *new_ctx = EVP_MD_CTX_new();
    int ret;

    if (!new_ctx)
        return 0;

    ret = EVP_MD_CTX_copy(new_ctx, fallback)
          && EVP_DigestUpdate(new_ctx, data, len)
          && EVP_DigestFinal_ex(new_ctx, res, NULL);

    EVP_MD_CTX_free(new_ctx);
    return ret;
}
#endif

static int digest_init(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int i = get_digest_data_index(EVP_MD_CTX_type(ctx));

    digest_ctx->sfd = -1;
    digest_ctx->digest_d = &digest_data[i];
#ifndef AFALG_NO_FALLBACK
    if (digest_fb_ctx[i]) {
        digest_ctx->fallback = digest_fb_ctx[i];
        digest_ctx->fb_threshold = digest_fb_threshold[i];
    }
#endif
    return 1;
}

static int digest_get_sfd(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    __u32 afalg_mask;
    const struct digest_data_st *digest_d = digest_ctx->digest_d;

    digest_ctx->sfd = -1;
    if (use_softdrivers == AFALG_REQUIRE_ACCELERATED)
        afalg_mask = CRYPTO_ALG_KERN_DRIVER_ONLY;
    else
        afalg_mask = 0;

    digest_ctx->bfd = get_afalg_socket(digest_d->name, "hash",
                                       afalg_mask, afalg_mask);
    if (digest_ctx->bfd < 0) {
        SYSerr(SYS_F_BIND, errno);
        return 0;
    }

    if ((digest_ctx->sfd = accept(digest_ctx->bfd, NULL, 0)) < 0)
        goto out;
#ifdef AFALG_ZERO_COPY
    if (pipe(digest_ctx->pipes) != 0)
        goto out;
#endif
    return 1;

out:
    close(digest_ctx->bfd);
    digest_ctx->bfd = -1;

    if (digest_ctx->sfd > -1) {
        close(digest_ctx->sfd);
        digest_ctx->sfd = -1;
    }

    return 0;
}

static int afalg_do_digest(EVP_MD_CTX *ctx, const void *data, size_t len,
                           int more)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int flags;
#ifdef AFALG_ZERO_COPY
    struct iovec iov;
    int use_zc = (len <= zc_maxsize) && (((size_t)data & pagemask) == 0);
#endif

#ifndef AFALG_NO_FALLBACK
    if (digest_ctx->sfd == -1 && digest_ctx->fallback && !more
        && len < (size_t)digest_ctx->fb_threshold
        && digest_use_fb(digest_ctx->fallback, data, len, digest_ctx->res))
           return 1;
#endif
    if (digest_ctx->sfd == -1 && !digest_get_sfd(ctx))
        return 0;
#ifdef AFALG_ZERO_COPY
    if (use_zc) {
        iov.iov_base = (void *)data;
        iov.iov_len = len;
        flags = SPLICE_F_GIFT & (more ? SPLICE_F_MORE : 0);
        return vmsplice(digest_ctx->pipes[1], &iov, 1, flags) == (ssize_t) len
            && splice(digest_ctx->pipes[0], NULL, digest_ctx->sfd, NULL, len,
                      flags) == (ssize_t) len;
    }
#endif
    flags = more ? MSG_MORE : 0;
    return send(digest_ctx->sfd, data, len, flags) == (ssize_t) len;
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    char *new_data;
    int ret = 0;

    if (len == 0)
        return 1;
    if (digest_ctx == NULL)
        return 0;
    if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT))
        return afalg_do_digest(ctx, data, len, 0);
    if (digest_ctx->inp_len == 0 && len >= AFALG_DIGEST_CACHE_SIZE)
        return afalg_do_digest(ctx, data, len, 1);
    if (len > AFALG_DIGEST_CACHE_MAXSIZE) {
        if (!afalg_do_digest(ctx, digest_ctx->inp_data,
                             digest_ctx->inp_len, 1))
            return 0;
        ret = afalg_do_digest(ctx, data, len, 1);
        goto reset_data;
    }
    new_data = OPENSSL_realloc(digest_ctx->inp_data,
                               digest_ctx->inp_len + len);
    if (!new_data) {
        ALG_WARN("%s\n", __func__);
        return 0;
    }
    memcpy(new_data + digest_ctx->inp_len, data, len);
    digest_ctx->inp_len += len;
    digest_ctx->inp_data = new_data;
    if (digest_ctx->inp_len < AFALG_DIGEST_CACHE_SIZE)
        return 1;

    ret = afalg_do_digest(ctx, digest_ctx->inp_data, digest_ctx->inp_len, 1);

reset_data:
    OPENSSL_free(digest_ctx->inp_data);
    digest_ctx->inp_data = NULL;
    digest_ctx->inp_len = 0;

    return ret;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    int len = EVP_MD_CTX_size(ctx);
    int ret = 0;

    if (digest_ctx == NULL)
        return 0;

    if (md == NULL)
        goto out;

    if (EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT)
        || afalg_do_digest(ctx, digest_ctx->inp_data,
                           digest_ctx->inp_len, 0)) {
        if (digest_ctx->sfd != -1) {
            ret = recv(digest_ctx->sfd, md, len, 0) == len;
        } else {
#ifndef AFALG_NO_FALLBACK
            memcpy(md, digest_ctx->res, len);
            ret = 1;
#endif
        }
    }

out:
    OPENSSL_free(digest_ctx->inp_data);
    digest_ctx->inp_data = NULL;
    digest_ctx->inp_len = 0;

    return ret;
}

static int digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct digest_ctx *digest_from =
        (struct digest_ctx *)EVP_MD_CTX_md_data(from);
    struct digest_ctx *digest_to =
        (struct digest_ctx *)EVP_MD_CTX_md_data(to);

    if (digest_from == NULL)
        return 1;

    if (digest_from->inp_len > 0) {
        digest_to->inp_data = OPENSSL_malloc(digest_from->inp_len);
        if (digest_to->inp_data == NULL) {
           ALG_WARN("%s\n", __func__);
           digest_to->inp_len = 0;

           return 0;
        }

        memcpy(digest_to->inp_data, digest_from->inp_data,
               digest_from->inp_len);
    }

    if (digest_from->sfd == -1)
        return 1;

    digest_to->sfd = digest_to->bfd = -1;
#ifdef AFALG_ZERO_COPY
    if (pipe(digest_to->pipes) != 0)
        return 0;
#endif
    if ((digest_to->bfd = dup(digest_from->bfd)) == -1) {
        ALG_WARN("%s\n", __func__);
        goto fail;
    }

    if ((digest_to->sfd = accept(digest_from->sfd, NULL, 0)) != -1)
        return 1;

    SYSerr(SYS_F_ACCEPT, errno);
fail:
#ifdef AFALG_ZERO_COPY
    close(digest_to->pipes[0]);
    close(digest_to->pipes[1]);
#endif
    if (digest_to->bfd != -1)
        close(digest_to->bfd);
    digest_to->sfd = digest_to->bfd = -1;

    return 0;
}

static int digest_cleanup(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (digest_ctx == NULL || digest_ctx->sfd == -1)
        return 1;

    return !(0
#ifdef AFALG_ZERO_COPY
             | afalg_closefd(digest_ctx->pipes[0])
             | afalg_closefd(digest_ctx->pipes[1])
#endif
             | afalg_closefd(digest_ctx->sfd)
             | afalg_closefd(digest_ctx->bfd));
}

/*
 * Keep tables of known nids, associated methods, selected digests, and
 * driver info.
 * Note that known_digest_nids[] isn't necessarily indexed the same way as
 * digest_data[] above, which the other tables are.
 */
static int known_digest_nids[OSSL_NELEM(digest_data)];
static int known_digest_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_MD *known_digest_methods[OSSL_NELEM(digest_data)] = { NULL, };
static int selected_digests[OSSL_NELEM(digest_data)];
static struct driver_info_st digest_driver_info[OSSL_NELEM(digest_data)];

#ifndef AFALG_NO_FALLBACK
static EVP_MD_CTX *get_digest_fb_ctx(const EVP_MD *type)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx || EVP_DigestInit_ex(ctx, type, NULL))
        return ctx;

    EVP_MD_CTX_free(ctx);
    return NULL;
}
#endif

static int afalg_test_digest(size_t digest_data_index)
{
    return (digest_driver_info[digest_data_index].status == AFALG_STATUS_USABLE
            && selected_digests[digest_data_index] == 1
            && (digest_driver_info[digest_data_index].accelerated
                    == AFALG_ACCELERATED
                || use_softdrivers == AFALG_USE_SOFTWARE
                || (digest_driver_info[digest_data_index].accelerated
                        != AFALG_NOT_ACCELERATED
                    && use_softdrivers == AFALG_REJECT_SOFTWARE)));
}

static void rebuild_known_digest_nids(ENGINE *e)
{
    size_t i;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data); i++) {
        if (afalg_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }

    ENGINE_unregister_digests(e);
    ENGINE_register_digests(e);
}

static void prepare_digest_methods(void)
{
    size_t i;
    int fd;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data);
         i++) {

        selected_digests[i] = 1;
        /*
         * Check that the digest is usable
         */
        if ((fd = get_afalg_socket(digest_data[i].name, "hash", 0, 0)) < 0) {
            digest_driver_info[i].status = AFALG_STATUS_NO_OPEN;
            continue;
        }
        close(fd);

        /* test hardware acceleration */
        if ((fd =
            get_afalg_socket(digest_data[i].name, "hash",
                             CRYPTO_ALG_KERN_DRIVER_ONLY,
                             CRYPTO_ALG_KERN_DRIVER_ONLY)) >= 0) {
            digest_driver_info[i].accelerated = AFALG_ACCELERATED;
            close(fd);
        } else {
            digest_driver_info[i].accelerated = AFALG_NOT_ACCELERATED;
        }

        if ((known_digest_methods[i] = EVP_MD_meth_new(digest_data[i].nid,
                                                       NID_undef)) == NULL
            || !EVP_MD_meth_set_input_blocksize(known_digest_methods[i],
                                                digest_data[i].blocksize)
            || !EVP_MD_meth_set_result_size(known_digest_methods[i],
                                            digest_data[i].digestlen)
            || !EVP_MD_meth_set_init(known_digest_methods[i], digest_init)
            || !EVP_MD_meth_set_update(known_digest_methods[i], digest_update)
            || !EVP_MD_meth_set_final(known_digest_methods[i], digest_final)
            || !EVP_MD_meth_set_copy(known_digest_methods[i], digest_copy)
            || !EVP_MD_meth_set_cleanup(known_digest_methods[i], digest_cleanup)
            || !EVP_MD_meth_set_app_datasize(known_digest_methods[i],
                                             sizeof(struct digest_ctx))) {
            digest_driver_info[i].status = AFALG_STATUS_FAILURE;
            EVP_MD_meth_free(known_digest_methods[i]);
            known_digest_methods[i] = NULL;

        } else {
#ifndef AFALG_NO_FALLBACK
            if (digest_data[i].fallback) {
                digest_fb_ctx[i] = get_digest_fb_ctx(digest_data[i].fallback());
                digest_fb_threshold[i] = digest_data[i].fb_threshold;
            }
#endif
            digest_driver_info[i].status = AFALG_STATUS_USABLE;
        }

        if (afalg_test_digest(i))
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
    }
}

static const EVP_MD *get_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    if (i == (size_t)-1)
        return NULL;

    return known_digest_methods[i];
}

static void destroy_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    EVP_MD_meth_free(known_digest_methods[i]);
    known_digest_methods[i] = NULL;
}

static void destroy_all_digest_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        destroy_digest_method(digest_data[i].nid);
}

static int afalg_digests(ENGINE *e, const EVP_MD **digest,
                             const int **nids, int nid)
{
    (void)e;
    if (digest == NULL) {
        *nids = known_digest_nids;
        return known_digest_nids_amount;
    }

    *digest = get_digest_method(nid);

    return *digest != NULL;
}

static void afalg_select_all_digests(int *digest_list)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        digest_list[i] = 1;
}

static int afalg_select_digest_cb(const char *str, int len, void *usr)
{
    int *digest_list = (int *)usr;
    char *name, *fb;
    const EVP_MD *EVP;
    size_t i;

    if (len == 0)
        return 1;
    if (usr == NULL || (name = OPENSSL_strndup(str, len)) == NULL)
        return 0;
    /* Even thought it is useful only with fallback enabled, keep the check here
     * so that the same config file works with or without AFALG_NO_FALLBACK */
    if ((fb = index(name, ':'))) {
        *(fb) = '\0';
        fb++;
    }

    EVP = EVP_get_digestbyname(name);
    if (EVP == NULL) {
        ALG_ERR("afalg: unknown digest %s\n", name);
    } else if ((i = find_digest_data_index(EVP_MD_type(EVP))) != (size_t)-1) {
        digest_list[i] = 1;
#ifndef AFALG_NO_FALLBACK
        if (fb && (digest_fb_threshold[i] = atoi(fb)) < 0) {
            digest_fb_threshold[i] = digest_data[i].fb_threshold;
        }
#endif
    } else {
        ALG_ERR("afalg: digest %s not available\n", name);
    }
    OPENSSL_free(name);
    return 1;
}

static void dump_digest_info(void)
{
    size_t i;
    const char *evp_name;
#ifndef AFALG_NO_CRYPTOUSER
    const char *driver_name;
#endif

    fprintf (stderr, "Information about digests supported by the AF_ALG"
             " engine:\n");

    for (i = 0; i < OSSL_NELEM(digest_data); i++) {
        evp_name = OBJ_nid2sn(digest_data[i].nid);
        fprintf (stderr, "Digest %s, NID=%d, AF_ALG info: name=%s",
                 evp_name ? evp_name : "unknown", digest_data[i].nid,
                 digest_data[i].name);
        if (digest_driver_info[i].status == AFALG_STATUS_NO_OPEN) {
            fprintf (stderr, ". AF_ALG socket bind failed.\n");
            continue;
        }
#ifndef AFALG_NO_CRYPTOUSER
        /* gather hardware driver information */
        if (afalg_alg_list_count > 0) {
            driver_name =
                afalg_get_driver_name(digest_data[i].name,
                                      digest_driver_info[i].accelerated);
        } else {
            driver_name = "unknown";
        }
        ALG_ERR(", driver=%s", driver_name);
#endif
        if (digest_driver_info[i].accelerated == AFALG_ACCELERATED)
            fprintf (stderr, " (hw accelerated)");
        else if (digest_driver_info[i].accelerated == AFALG_NOT_ACCELERATED)
            printf(" (software)");
        else
            printf(" (acceleration status unknown)");
        if (digest_driver_info[i].status == AFALG_STATUS_FAILURE)
            fprintf (stderr, ". Digest setup failed.");
        fprintf (stderr, "\n");
    }
    printf("\n");
}

#endif /* AFALG_DIGESTS */

/******************************************************************************
 *
 * Asymmetric
 *
 *****/
struct rsa_ctx {
    int bfd;
    int sfd;
    int is_connect;
    u_char *e;
    u_char *n;
    int e_sz;
    int n_sz;
    u_char *ber_key;
    int ber_key_len;
};

static RSA_METHOD *afalg_rsa_methods;
static struct rsa_ctx *rsa_ctx = NULL;

/* For kernel-6.6 */
#define ALG_SET_PUBKEY          8

#define _tag(CLASS, CP, TAG)    \
        (uint8_t)((V_ASN1_##CLASS << 6) | ((V_ASN1_##CP & 0x20) << 5) | V_ASN1_##TAG)

static int dbg_dump = 0;

static void hex_dump(char *name, u_char *str, int len)
{
	int i;

	if (!dbg_dump)
		return;

	printf("Hex dump %s (len:%d):", name, len);
	for (i = 0; i < len; i++)
	{
		if (i % 16 == 0)
			printf("\n");
		printf("0x%02x ", str[i]);
	}
	printf("\n\n");
}

static int ber_wr_tag(uint8_t **ber_ptr, uint8_t tag)
{
        **ber_ptr = tag;
        *ber_ptr += 1;

        return 0;
}

static int ber_wr_len(uint8_t **ber_ptr, size_t len, size_t sz)
{
        if (len < 127) {
                **ber_ptr = len;
                *ber_ptr += 1;
        } else {
                size_t sz_save = sz;

                sz--;
                **ber_ptr = 0x80 | sz;

                while (sz > 0) {
                        *(*ber_ptr + sz) = len & 0xff;
                        len >>= 8;
                        sz--;
                }
                *ber_ptr += sz_save;
        }

        return 0;
}

static int ber_wr_int(uint8_t **ber_ptr, uint8_t *src, size_t sz)
{
        memcpy(*ber_ptr, src, sz);
        *ber_ptr += sz;

        return 0;
}

/* calculate the size of the length field itself in BER encoding */
static size_t ber_enc_len(size_t len)
{
        size_t sz;

        sz = 1;
        if (len > 127) {                /* long encoding */
                while (len != 0) {
                        len >>= 8;
                        sz++;
                }
        }

        return sz;
}
static int asn1_ber_encoding(void)
{
    int e_sz, n_sz, s_sz;
    int e_enc_len;
    int n_enc_len;
    int s_enc_len;
    int err;
    u_char *ber_ptr;

    e_sz = rsa_ctx->e_sz;
    n_sz = rsa_ctx->n_sz;

    e_enc_len = ber_enc_len(e_sz);
    n_enc_len = ber_enc_len(n_sz);

    /*
     * Sequence length is the size of all the fields following the sequence
     * tag, added together. The two added bytes account for the two INT
     * tags in the Public Key sequence
     */
    s_sz = e_sz + e_enc_len + n_sz + n_enc_len + 2;
    s_enc_len = ber_enc_len(s_sz);

    /* The added byte accounts for the SEQ tag at the start of the key */
    rsa_ctx->ber_key_len = s_sz + s_enc_len + 1;

    rsa_ctx->ber_key = OPENSSL_zalloc(rsa_ctx->ber_key_len);
    if (!rsa_ctx->ber_key) {
            ALG_WARN("%s: ber key allocation failed\n", __func__);
            return -EINVAL;
    }

    memset(rsa_ctx->ber_key, 0, rsa_ctx->ber_key_len);
    ber_ptr = rsa_ctx->ber_key;

    err = ber_wr_tag(&ber_ptr, _tag(UNIVERSAL, CONSTRUCTED, SEQUENCE))  ||
          ber_wr_len(&ber_ptr, s_sz, s_enc_len)                         ||
          ber_wr_tag(&ber_ptr, _tag(UNIVERSAL, PRIMITIVE_TAG, INTEGER)) ||
          ber_wr_len(&ber_ptr, n_sz, n_enc_len)                         ||
          ber_wr_int(&ber_ptr, rsa_ctx->n, n_sz)                        ||
          ber_wr_tag(&ber_ptr, _tag(UNIVERSAL, PRIMITIVE_TAG, INTEGER)) ||
          ber_wr_len(&ber_ptr, e_sz, e_enc_len)                         ||
          ber_wr_int(&ber_ptr, rsa_ctx->e, e_sz);
    if (err) {
        ALG_WARN("%s: gen ber key failed\n", __func__);
        goto free_key;
    }

    return 0;

free_key:
    if (rsa_ctx->ber_key)
        OPENSSL_free(rsa_ctx->ber_key);

    return -EINVAL;
}

static int afalg_set_pubkey(const BIGNUM *e, const BIGNUM *n)
{
    u_char *key = NULL;
    int len, len_e, len_n;
    int ret;

    ALG_DBG("%s\n", __func__);

    /* transfer BN to binary & remove leading zero */
    len = len_e = BN_num_bytes(e);
    key = OPENSSL_zalloc(len);
    if (!len || !key) {
        ALG_WARN("%s: key allocation failed, len = %d\n", __func__, len);
        goto err;
    }

    BN_bn2bin(e, key);
    hex_dump("key", key, len);

    rsa_ctx->e = OPENSSL_zalloc(len);
    if (rsa_ctx->e == NULL) {
        ALG_WARN("%s: rsa_ctx->e allocation failed, len = %d\n", __func__, len);
        goto err;
    }
    memcpy(rsa_ctx->e, key, len);
    rsa_ctx->e_sz = len;
    OPENSSL_free(key);

    hex_dump("e", rsa_ctx->e, len);

    len = len_n = BN_num_bytes(n);
    key = OPENSSL_zalloc(len);
    if (!len || !key)
        goto err;

    BN_bn2bin(n, key);
    hex_dump("key", key, len);
    while (len > 0 && (key[0] == 0)) {
        len--;
        key++;
    }

    rsa_ctx->n = OPENSSL_zalloc(len);
    if (rsa_ctx->n == NULL) {
        ALG_WARN("%s: rsa_ctx->n allocation failed, len = %d\n", __func__, len);
        goto err;
    }
    memcpy(rsa_ctx->n, key, len);
    rsa_ctx->n_sz = len;
    OPENSSL_free(key);
    key = NULL;

    hex_dump("n", rsa_ctx->n, len);

    /* Convert key to BER format */
    ret = asn1_ber_encoding();
    if (ret) {
        ALG_WARN("%s: asn1 ber encoding failed\n", __func__);
        goto err;
    }

    /* Set public key */
    ret = afalg_set_key(rsa_ctx->bfd, rsa_ctx->ber_key, rsa_ctx->ber_key_len,
                        ALG_SET_PUBKEY);
    if (!ret) {
        ALG_WARN("%s: afalg set pubkey failed\n", __func__);
        goto err;
    }

    return 0;

err:
    if (key)
        OPENSSL_free(key);
    return -1;
}

static int afalg_asym_cipher_init(BIGNUM *e, BIGNUM *n)
{
    int ret;

    ALG_DBG("%s\n", __func__);
    /* Start connecting akcipher */
    if (!rsa_ctx) {
        rsa_ctx = OPENSSL_malloc(sizeof(struct rsa_ctx));
        if (!rsa_ctx) {
            ALG_WARN("%s: rsa_ctx allocation failed\n", __func__);
            return -ENOMEM;
        }
    }

    rsa_ctx->is_connect = 0;
    rsa_ctx->sfd = -1;
    rsa_ctx->bfd = get_afalg_socket("rsa", "akcipher", 0, 0);

    if (rsa_ctx->bfd < 0) {
        SYSerr(SYS_F_BIND, errno);
        ALG_WARN("%s: bind afalg socket failed\n", __func__);
        return errno;
    }

    if ((rsa_ctx->sfd = accept(rsa_ctx->bfd, NULL, 0)) < 0) {
        ret = rsa_ctx->sfd;
        ALG_WARN("%s: accept afalg socket failed\n", __func__);
        goto accept_fail;
    }

    /* Set public key */
    ret = afalg_set_pubkey(e, n);
    if (ret) {
        ALG_WARN("%s: set pubkey failed\n", __func__);
        goto fail;
    }

    rsa_ctx->is_connect = 1;

    return 0;

fail:
    afalg_closefd(rsa_ctx->sfd);

accept_fail:
    afalg_closefd(rsa_ctx->bfd);
    rsa_ctx->sfd = rsa_ctx->bfd = -1;

    if (rsa_ctx) {
        OPENSSL_free(rsa_ctx);
        rsa_ctx = NULL;
    }

    return ret;
}

static void afalg_asym_cipher_exit(void)
{
    if (!rsa_ctx)
        return;

    if (rsa_ctx->is_connect) {
        afalg_closefd(rsa_ctx->sfd);
        afalg_closefd(rsa_ctx->bfd);
    }

    rsa_ctx->sfd = rsa_ctx->bfd = -1;

    if (rsa_ctx->ber_key)
        OPENSSL_free(rsa_ctx->ber_key);
    if (rsa_ctx->n)
        OPENSSL_free(rsa_ctx->n);
    if (rsa_ctx->e)
        OPENSSL_free(rsa_ctx->e);
    if (rsa_ctx) {
        OPENSSL_free(rsa_ctx);
        rsa_ctx = NULL;
    }
}

static int afalg_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                            const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    struct msghdr msg = {0};
    struct iovec iov = {0};
    u_char *bin_a, *bin_r;
    int len_a, len_r, len_m;
    int pad_len;
    int ret;
    int op;

    ALG_DBG("%s\n", __func__);
    ret = afalg_asym_cipher_init((BIGNUM *)p, (BIGNUM *)m);
    if (ret) {
        /* Hardware failed, use software */
        const RSA_METHOD *meth = RSA_PKCS1_OpenSSL();
        ret = RSA_meth_get_bn_mod_exp(meth)(r, a, p, m, ctx, in_mont);
        ALG_WARN("%s: hardware failed, use software\n", __func__);

        goto init_fail;
    }

    op = ALG_OP_ENCRYPT;
    ret = afalg_set_control(&msg, op, NULL, 0);
    if (!ret) {
        ALG_WARN("%s: set control failed\n", __func__);
        goto init_fail;
    }

    len_m = BN_num_bytes(m);
    len_a = BN_num_bytes(a);
    pad_len = len_m - len_a;

    ALG_DBG("pad_len:%d\n", pad_len);

    len_r = rsa_ctx->n_sz;

    /* inputs: a^p % m */
    bin_a = OPENSSL_zalloc(len_m);
    bin_r = OPENSSL_zalloc(len_r);
    if (!bin_a || !bin_r) {
        ALG_WARN("%s: allocate a/r failed\n", __func__);
        goto fail;
    }

    memset(bin_a, 0, len_m);
    memset(bin_r, 0, len_r);
    BN_bn2bin(a, bin_a + pad_len);

    hex_dump("a", bin_a, len_m);

    iov.iov_base = (void *)bin_a;
    iov.iov_len = len_m;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if ((ret = sendmsg(rsa_ctx->sfd, &msg, 0)) < 0) {
            ALG_WARN("%s: sendmsg failed, ret:0x%x, errno:0x%x\n",
                        __func__, ret, errno);
        ret = 0;
            goto fail;
    }

    ALG_DBG("%s: sendmsg, len:0x%x, ret:0x%x\n", __func__, len_a, ret);
    iov.iov_base = (void *)bin_r;
    iov.iov_len = len_r;

    if ((ret = read(rsa_ctx->sfd, bin_r, len_r)) < 0) {
        ALG_WARN("%s: recvmsg failed, ret:0x%x, errno:0x%x\n",
                __func__, ret, errno);
        ret = 0;
        goto fail;

    }

    hex_dump("r", bin_r, len_r);
    ALG_DBG("%s: recvmsg, len:0x%x, ret:0x%x\n", __func__, len_r, ret);

    BN_bin2bn(bin_r, ret, r);
    ret = 1;    /* successful */

fail:
    if (msg.msg_control)
        OPENSSL_free(msg.msg_control);
    if (bin_a)
        OPENSSL_free(bin_a);
    if (bin_r)
        OPENSSL_free(bin_r);

init_fail:
    afalg_asym_cipher_exit();

    return ret;
}

static void prepare_asym_cipher_methods(void)
{
    if (afalg_rsa_methods)
        return;

    if ((afalg_rsa_methods = RSA_meth_dup(RSA_PKCS1_OpenSSL())) == NULL
        || !RSA_meth_set1_name(afalg_rsa_methods, "afalg RSA method")
        || !RSA_meth_set_flags(afalg_rsa_methods, 0)
        || !RSA_meth_set_bn_mod_exp(afalg_rsa_methods, afalg_bn_mod_exp)
        ) {
            ALG_WARN("%s: allocate RSA methods failed\n", __func__);
            RSA_meth_free(afalg_rsa_methods);
            afalg_rsa_methods = NULL;
            return;
    }
}

/******************************************************************************
 *
 * CONTROL COMMANDS
 *
 *****************************************************************************/

enum {
    AFALG_CMD_USE_SOFTDRIVERS = ENGINE_CMD_BASE,
    AFALG_CMD_CIPHERS,
#ifdef AFALG_DIGESTS
    AFALG_CMD_DIGESTS,
#endif
    AFALG_CMD_DUMP_INFO
};

/* Helper macros for CPP string composition */
#ifndef OPENSSL_MSTR
#define OPENSSL_MSTR_HELPER(x) #x
#define OPENSSL_MSTR(x) OPENSSL_MSTR_HELPER(x)
#endif

static const ENGINE_CMD_DEFN afalg_cmds[] = {
    {AFALG_CMD_USE_SOFTDRIVERS,
    "USE_SOFTDRIVERS",
    "specifies whether to use software (not accelerated) drivers ("
        OPENSSL_MSTR(AFALG_REQUIRE_ACCELERATED) "=use only accelerated drivers, "
        OPENSSL_MSTR(AFALG_USE_SOFTWARE) "=allow all drivers, "
        OPENSSL_MSTR(AFALG_REJECT_SOFTWARE)
        "=use if acceleration can't be determined) [default="
        OPENSSL_MSTR(AFALG_DEFAULT_USE_SOFTDRIVERS) "]",
    ENGINE_CMD_FLAG_NUMERIC},

    {AFALG_CMD_CIPHERS,
     "CIPHERS",
     "either ALL, NONE, NO_ECB (all except ECB-mode) or a comma-separated"
     " list of ciphers to enable"
#ifndef AFALG_NO_FALLBACK
     ". If you use a list, each cipher may be followed by a colon (:) and the"
     " minimum request length to use AF_ALG drivers for that cipher; smaller"
     " requests are processed by softare; a negative value will use the"
     " default for that cipher; use DUMP_INFO to see the ciphers that support"
     " software fallback, and their default values"
#endif
     " [default=NO_ECB]",
     ENGINE_CMD_FLAG_STRING},

#ifdef AFALG_DIGESTS
   {AFALG_CMD_DIGESTS,
     "DIGESTS",
     "either ALL, NONE, or a comma-separated list of digests to enable"
#ifndef AFALG_NO_FALLBACK
     ". If you use a list, each digest may be followed by a colon (:) and the"
     " minimum request length to use AF_ALG drivers for that digest; a negative"
     " value will use the default (16384) for that digest"
#endif
     " [default=NONE]",
     ENGINE_CMD_FLAG_STRING},
#endif

   {AFALG_CMD_DUMP_INFO,
     "DUMP_INFO",
     "dump info about each algorithm to stderr; use 'openssl engine -pre DUMP_INFO afalg'",
     ENGINE_CMD_FLAG_NO_INPUT},

    {0, NULL, NULL, 0}
};

static int afalg_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int *new_list;

    (void)e;
    (void)f;
    switch(cmd) {
    case AFALG_CMD_USE_SOFTDRIVERS:
        switch(i) {
        case AFALG_REQUIRE_ACCELERATED:
        case AFALG_USE_SOFTWARE:
        case AFALG_REJECT_SOFTWARE:
            break;
        default:
            ALG_ERR("afalg: invalid value (%ld) for USE_SOFTDRIVERS\n", i);
            return 0;
        }

        if (use_softdrivers == i)
            return 1;

        use_softdrivers = i;
#ifdef AFALG_DIGESTS
        rebuild_known_digest_nids(e);
#endif
        rebuild_known_cipher_nids(e);
        return 1;

    case AFALG_CMD_CIPHERS:
        if (p == NULL)
            return 1;
        if (strcasecmp((const char *)p, "NO_ECB") == 0) {
            afalg_select_all_ciphers(selected_ciphers, 0);

        } else if (strcasecmp((const char *)p, "ALL") == 0) {
            afalg_select_all_ciphers(selected_ciphers, 1);

        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_ciphers, 0, sizeof(selected_ciphers));

        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_ciphers));
            if (new_list == NULL) {
                fprintf (stderr, "Failed to allocate memory for new_list, %zu\n", sizeof(selected_ciphers));
                return 0;
            }
            if (!CONF_parse_list(p, ',', 1, afalg_select_cipher_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }

            memcpy(selected_ciphers, new_list, sizeof(selected_ciphers));
            OPENSSL_free(new_list);
        }

        rebuild_known_cipher_nids(e);
        return 1;

#ifdef AFALG_DIGESTS
    case AFALG_CMD_DIGESTS:
        if (p == NULL)
            return 1;

        if (strcasecmp((const char *)p, "ALL") == 0) {
            afalg_select_all_digests(selected_digests);

        } else if (strcasecmp((const char*)p, "NONE") == 0) {
            memset(selected_digests, 0, sizeof(selected_digests));

        } else {
            new_list=OPENSSL_zalloc(sizeof(selected_digests));
            if (new_list == NULL) {
                fprintf (stderr, "Failed to allocate memory for new_list, %zu\n", sizeof(selected_digests));
                return 0;
            }
            if (!CONF_parse_list(p, ',', 1, afalg_select_digest_cb, new_list)) {
                OPENSSL_free(new_list);
                return 0;
            }

            memcpy(selected_digests, new_list, sizeof(selected_digests));
            OPENSSL_free(new_list);
        }

        rebuild_known_digest_nids(e);
        return 1;
#endif

    case AFALG_CMD_DUMP_INFO:
#ifndef AFALG_NO_CRYPTOUSER
        prepare_afalg_alg_list();
        if (afalg_alg_list_count < 0)
            fprintf (stderr, "Could not get driver info through the netlink"
                     " interface.\nIs the 'crypto_user' module loaded?\n");
#endif
        dump_cipher_info();
#ifdef AFALG_DIGESTS
        dump_digest_info();
#endif
        return 1;

    default:
        break;
    }
    return 0;
}

/******************************************************************************
 *
 * LOAD / UNLOAD
 *
 *****************************************************************************/

static int afalg_unload(ENGINE *e)
{
    (void)e;
    destroy_all_cipher_methods();
#ifdef AFALG_DIGESTS
    destroy_all_digest_methods();
#endif

    return 1;
}


static int bind_afalg(ENGINE *e) {
    int ret;

    if (!ENGINE_set_id(e, engine_afalg_id)
        || !ENGINE_set_name(e, "AF_ALG engine")
        || !ENGINE_set_destroy_function(e, afalg_unload)
        || !ENGINE_set_cmd_defns(e, afalg_cmds)
        || !ENGINE_set_ctrl_function(e, afalg_ctrl))
        return 0;

#ifdef AFALG_ZERO_COPY
    pagemask = sysconf(_SC_PAGESIZE) - 1;
    zc_maxsize = sysconf(_SC_PAGESIZE) * 16;
#endif
    prepare_cipher_methods();
#ifdef AFALG_DIGESTS
    prepare_digest_methods();
#endif
    prepare_asym_cipher_methods();

    OPENSSL_free(afalg_alg_list);
    if (afalg_alg_list_count > 0)
        afalg_alg_list_count = 0;
    ret = ENGINE_set_ciphers(e, afalg_ciphers);
#ifdef AFALG_DIGESTS
    ret = ret && ENGINE_set_digests(e, afalg_digests);
#endif
    ret = ret && ENGINE_set_RSA(e, afalg_rsa_methods);

    return ret;
}

static int test_afalg_socket(void)
{
    int sock;

    /* Test if we can actually create an AF_ALG socket */
    sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        ALG_ERR("Could not create AF_ALG socket: %s\n", strerror(errno));
        return 0;
    }

    close(sock);
    return 1;
}

static int bind_helper(ENGINE *e, const char *id)
{
    if ((id && (strcmp(id, engine_afalg_id) != 0))
        || !test_afalg_socket())
        return 0;

    if (!bind_afalg(e))
        return 0;

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
