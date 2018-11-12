//
// Created by Rqg on 2018/11/5.
//

#ifndef ENVPROXY_GENRSA_H
#define ENVPROXY_GENRSA_H

#include <openssl/ossl_typ.h>

#define ERR_print_errors_aloge() BIO *bio_err = BIO_new(BIO_s_mem()); \
                                auto err_len = BIO_ctrl_pending(bio_err); \
                                char *err = static_cast<char *>(malloc(err_len + 1)); \
                                memset(err, 0, err_len + 1); \
                                ERR_print_errors(bio_err); \
                                BIO_get_mem_data(bio_err, &err); \
                                BIO_free_all(bio_err); \
                                ALOGE("%s", err); \


BIO *genrsaAes256l2048();

int req_main(BIO *pkeyBio);

int password_callback(char *buf, int bufsiz, int verify, void *cb_tmp);

#endif //ENVPROXY_GENRSA_H
