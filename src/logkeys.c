#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <execinfo.h>
#include <stdlib.h>
#include <errno.h>
#include <sodium/crypto_box.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef int (*orig_crypto_box_keypair_type)(unsigned char *pk, unsigned char *sk);
static void do_export_keypair(const char *name, const uint8_t *public_key, const uint8_t *private_key);

int crypto_box_keypair(unsigned char *pk, unsigned char *sk)
{
    void *array[20];
    size_t size;
    char **strings;
    size_t i;
    const char *name = "name";
    bool export = true;

    size = backtrace(array, 20);
    strings = backtrace_symbols(array, size);
    //printf("got trace going back %d frames\n", size);
    if (size >= 2) {
        printf("caller is %s\n",strings[1]);
    }
    //for (i=1; i< size; i++) {
    //    printf("%d %s\n", i, strings[i]);
    //}
    /* Some evil injected code goes here. */
    //printf("crypto_box_keypair(%p,%p)\n", pk, sk);
 
    orig_crypto_box_keypair_type orig_crypto_box_keypair;
    orig_crypto_box_keypair =
        (orig_crypto_box_keypair_type)dlsym(RTLD_NEXT,"crypto_box_keypair");
    int ret = orig_crypto_box_keypair(pk, sk);
    if (size >= 2) {
        if (strstr(strings[1], "create_onion_path")) {
            name = "onion";
            export = false;
        } else if (strstr(strings[1], "new_DHT")) {
            name = "DHT";
        }
        if (export) {
            do_export_keypair(name, pk, sk);
        }
    }
    free(strings);
    return ret;
}

static FILE *keyfile = 0;
static bool keyfile_did_init = false;

static void do_export_keypair(const char *name, const uint8_t *public_key, const uint8_t *private_key)
{
    int i;

    if (!keyfile_did_init) {
        char *value = getenv("TOX_LOG_KEYS");

        if (value) {
            keyfile = fopen(value, "a");

            if (!keyfile) {
                fprintf(stderr, "unable to open %s: %s\n", value, strerror(errno));
            }
        }

        keyfile_did_init = true;
    }

    if (keyfile) {
        fprintf(keyfile, "%s ", name);

        for (i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
            fprintf(keyfile, "%02x", public_key[i]);
        }

        fprintf(keyfile, " ");

        for (i = 0; i < crypto_box_SECRETKEYBYTES; i++) {
            fprintf(keyfile, "%02x", private_key[i]);
        }

        fprintf(keyfile, "\n");
        fflush(keyfile);
    }
}