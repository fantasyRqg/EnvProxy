//
// Created by Rqg on 2018/10/25.
//

#ifndef ENVPROXY_CERTMANAGER_H
#define ENVPROXY_CERTMANAGER_H

#include <map>
#include <string>
#include <openssl/ossl_typ.h>

struct SSLCert;

class CertManager {
public:
    SSLCert *getSSLCtx(std::string hostName);

private:
    std::map<std::string, SSLCert *> certMap;
};


#endif //ENVPROXY_CERTMANAGER_H
