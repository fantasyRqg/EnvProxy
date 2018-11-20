//
// Created by Rqg on 2018/10/25.
//


#ifndef ENVPROXY_TLS_SERVER_NAME
#define ENVPROXY_TLS_SERVER_NAME

#include <inttypes.h>

int parse_tls_header(const uint8_t *data, size_t data_len, char **hostname);

#endif
