//
// Created by Rqg on 2018/11/5.
//

#include <openssl/ossl_typ.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <cstring>
#include "../log.h"

# define DEFBITS 2048
# define DEFPRIMES 2

#define LOG_TAG "genrsa"

static int genrsa_cb(int p, int n, BN_GENCB *cb);

int password_callback(char *buf, int bufsiz, int verify, void *cb_tmp);

BIO *genrsa_main() {

    BIO *bio_err = BIO_new(BIO_s_mem());

    BN_GENCB *cb = BN_GENCB_new();
    BIGNUM *bn = BN_new();
    BIO *out = BIO_new(BIO_s_mem());
    const BIGNUM *e;
    RSA *rsa = NULL;
    const EVP_CIPHER *enc = EVP_get_cipherbyname("aes256");
    int ret = 1, num = DEFBITS, primes = DEFPRIMES;
    unsigned long f4 = RSA_F4;
    char *outfile = NULL, *passoutarg = NULL, *passout = NULL;
    char *prog, *hexe, *dece;

    if (bn == NULL || cb == NULL)
        goto end;

    BN_GENCB_set(cb, genrsa_cb, bio_err);

    ALOGI("Generating RSA private key, %d bit long modulus (%d primes)\n", num, primes);

    rsa = RSA_new();
    if (rsa == NULL)
        goto end;

    if (!BN_set_word(bn, f4)
        || !RSA_generate_multi_prime_key(rsa, num, primes, bn, cb))
        goto end;

    RSA_get0_key(rsa, NULL, &e, NULL);
    hexe = BN_bn2hex(e);
    dece = BN_bn2dec(e);
    if (hexe && dece) {
        BIO_printf(bio_err, "e is %s (0x%s)\n", dece, hexe);
    }
    OPENSSL_free(hexe);
    OPENSSL_free(dece);

    if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0,
                                     (pem_password_cb *) password_callback, nullptr))
        goto end;

    ret = 0;
    end:
    BN_free(bn);
    BN_GENCB_free(cb);
    RSA_free(rsa);
//    BIO_free_all(out);
    OPENSSL_free(passout);
    if (ret != 0) {
        char *err;
        ERR_print_errors(bio_err);
        BIO_get_mem_data(bio_err, &err);
        ALOGE("%s", err);
        return nullptr;
    }

    return out;
}


int password_callback(char *buf, int bufsiz, int verify, void *cb_tmp) {
    strcpy(buf, "1234567890");
    return 1;
}

int genrsa_cb(int p, int n, BN_GENCB *cb) {
//    ALOGD("genrsa_cb: %d", p);
    return 1;
}

BIO *genrsaAes256l2048() {
    return genrsa_main();
}
