# OpenSSL `ast_crypto_engine` Usage Guide

## Introduction
`ast_crypto_engine` is an openssl plugin based on the Linux AF_ALG implementation. This plugin helps pass the data to HW crypto engine for further operations.

## Usage
This section provides examples in different scenarios.

### Dump Current Supported Methods
```sh
openssl engine -pre DUMP_INFO ast_crypto_engine
```
#### Result
```text
...
Information about digests supported by the AF_ALG engine:
Digest MD5, NID=4, AF_ALG info: name=md5. AF_ALG socket bind failed.
Digest SHA1, NID=64, AF_ALG info: name=sha1ALG_ERR: , driver=unknown (hw accelerated)
Digest SHA224, NID=675, AF_ALG info: name=sha224ALG_ERR: , driver=unknown (hw accelerated)
Digest SHA256, NID=672, AF_ALG info: name=sha256ALG_ERR: , driver=unknown (hw accelerated)
Digest SHA384, NID=673, AF_ALG info: name=sha384ALG_ERR: , driver=unknown (hw accelerated)
Digest SHA512, NID=674, AF_ALG info: name=sha512ALG_ERR: , driver=unknown (hw accelerated)
...
```

### Generate a SHA256 Digest
```sh
dd if=/dev/random of=/tmp/rdata bs=1k count=1k
openssl dgst -sha256 -engine ast_crypto_engine /tmp/rdata
```
#### Result
```text
Engine "ast_crypto_engine" set.
SHA2-256(/tmp/rdata)= 050074e1cb89b364da0933901ff22c9167480120ebe494b5ff76fe22a8c30e8b
```

### Run AES-128-CBC Performance Test
```sh
openssl speed -elapsed -engine ast_crypto_engine aes-128-cbc
```
#### Result
```text
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
aes-128-cbc        381.26k     1502.36k     5884.50k    21619.37k    91231.57k   117926.57k
```
#### Result (without ast_crypto_engine)
```text
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
aes-128-cbc      22826.54k    28431.57k    30384.98k    30912.51k    31069.53k    31064.06k
```

### Code Sample
```c
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <string.h>

int main() {
    int ret = 1;
    ENGINE *e = NULL;
    EVP_MD_CTX *mdctx = NULL;
    ENGINE_load_builtin_engines();

    // load engine
    e = ENGINE_by_id("ast_crypto_engine");
    if (!e) {
        fprintf(stderr, "Engine not found.\n");
        return 1;
    }

    if (!ENGINE_init(e)) {
        fprintf(stderr, "Engine initialization failed.\n");
        goto cleanup;
    }

    printf("%s loaded successfully\n", ENGINE_get_name(e));

    // Do SHA384
    const char *message = "Hello, OpenSSL Engine!";
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    const EVP_MD *md = EVP_sha384();

    if (!md) {
        fprintf(stderr, "Failed to get SHA-384 method.\n");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX.\n");
        goto cleanup;
    }

    if (!EVP_DigestInit_ex(mdctx, md, e)) {
        fprintf(stderr, "EVP_DigestInit_ex failed.\n");
        goto cleanup;
    }

    if (!EVP_DigestUpdate(mdctx, message, strlen(message))) {
        fprintf(stderr, "EVP_DigestUpdate failed.\n");
        goto cleanup;
    }

    if (!EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        fprintf(stderr, "EVP_DigestFinal_ex failed.\n");
        goto cleanup;
    }

    ret = 0;
    printf("SHA-384 hash: ");
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // release resources
cleanup:
    if (mdctx)
        EVP_MD_CTX_free(mdctx);
    if (e) {
        ENGINE_finish(e);
        ENGINE_free(e);
    }

    return ret;
}
```
Note: Current `ast_crypto_engine` is based on the Engine APIs that will be deprecated in the future.