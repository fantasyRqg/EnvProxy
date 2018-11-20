//
// Created by Rqg on 2018/10/25.
//

#ifndef ENVPROXY_CERTMANAGER_H
#define ENVPROXY_CERTMANAGER_H

#include <map>
#include <openssl/ossl_typ.h>
#include <jni.h>
#include <string>
#include <cstring>

struct SSLCert;

class proxyEngine;

class CertManager {
public:

    CertManager(proxyEngine *engine, const char *certsDirPath, const char *keyFilePath);

    SSLCert *getSSLCtx(char *hostName);

    virtual ~CertManager();

private:
    struct cmp_str {
        bool operator()(char const *a, char const *b) {
            return std::strcmp(a, b) < 0;//比较字符串的内容
        }
    };

    SSLCert *loadCertFromFile(const char *path);


private:
    std::map<char *, SSLCert *, cmp_str> certsMap;
    proxyEngine *engine = nullptr;
    char *certsDirPath = nullptr;
    char *keyFilePath = nullptr;


    SSL_CTX *commonClientCtx = nullptr;


};


#endif //ENVPROXY_CERTMANAGER_H
