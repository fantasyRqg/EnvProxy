//
// Created by Rqg on 2018/11/9.
//



#include <openssl/ossl_typ.h>
#include <openssl/safestack.h>
#include <openssl/lhash.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <cstring>
#include "../log.h"
#include "reqConfig.h"
#include "ssl.h"


#define LOG_TAG "ssl_req"


#define SECTION         "req"

#define BITS            "default_bits"
#define KEYFILE         "default_keyfile"
#define PROMPT          "prompt"
#define DISTINGUISHED_NAME      "distinguished_name"
#define ATTRIBUTES      "attributes"
#define V3_EXTENSIONS   "x509_extensions"
#define REQ_EXTENSIONS  "req_extensions"
#define STRING_MASK     "string_mask"
#define UTF8_IN         "utf8"


int set_cert_times(X509 *x, const char *startdate, const char *enddate,
                   int days);

int opt_md(const char *name, const EVP_MD **mdp);

CONF *app_load_config();

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts);

int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value);

int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts);

int provideInfo(X509_REQ *req, unsigned long chtype);

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, int attribs, unsigned long chtype, CONF *req_conf);

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai) {
    BIGNUM *btmp;
    int ret = 0;

    btmp = b == NULL ? BN_new() : b;
    if (btmp == NULL)
        return 0;

# define SERIAL_RAND_BITS        159

    if (!BN_rand(btmp, SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;

    ret = 1;

    error:

    if (btmp != b)
        BN_free(btmp);

    return ret;
}

int req_main(BIO *pkeyBio, bool isReq) {
    ASN1_INTEGER *serial = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    STACK_OF(OPENSSL_STRING) *pkeyopts = NULL, *sigopts = NULL;
    LHASH_OF(OPENSSL_STRING) *addexts = NULL;
    X509 *x509ss = NULL;
    X509_REQ *req = NULL;
    const EVP_MD *md_alg = NULL, *digest = NULL;
    BIO *addext_bio = NULL;
    const char *extensions = NULL;
    char *keyalgstr = NULL;
    int ret = 1, x509 = 0, days = 0, i = 0;
    unsigned long chtype = MBSTRING_ASC;
    CONF *req_conf = NULL;

    size_t outLen;
    char *outStr;

    BIO *out;
    EVP_PKEY *tpubkey;



    //custom
    x509 = 1;
    PEM_read_bio_PrivateKey(pkeyBio, &pkey, password_callback, nullptr);
    days = 3000;
    opt_md("sha256", &md_alg);
    digest = md_alg;
    req_conf = app_load_config();

    if (isReq) {
        extensions = NULL;
    } else {
        extensions = "v3_ca";
    }


    if (!ASN1_STRING_set_default_mask_asc("utf8only")) {
        ALOGE("Invalid global string mask setting utf8only");
        goto end;
    }


    if (pkey == NULL) {
        ALOGE("you need to specify a private key");
        goto end;
    }

    {
        req = X509_REQ_new();
        if (req == NULL) {
            goto end;
        }

        i = make_REQ(req, pkey, !x509, chtype, req_conf);
        if (!i) {
            ALOGE("problems making Certificate Request");
            goto end;
        }
    }

    {

        EVP_PKEY *tmppkey;
        X509V3_CTX ext_ctx;
        if ((x509ss = X509_new()) == NULL)
            goto end;
        if (!X509_set_version(x509ss, 2))
            goto end;

        if (!rand_serial(NULL, X509_get_serialNumber(x509ss)))
            goto end;

        if (!X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req)))
            goto end;

        if (!set_cert_times(x509ss, NULL, NULL, days))
            goto end;
        if (!X509_set_subject_name
                (x509ss, X509_REQ_get_subject_name(req)))
            goto end;
        tmppkey = X509_REQ_get0_pubkey(req);
        if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey))
            goto end;
        X509V3_set_ctx(&ext_ctx, x509ss, x509ss, NULL, NULL, 0);
        X509V3_set_nconf(&ext_ctx, req_conf);

        if (extensions != NULL && !X509V3_EXT_add_nconf(req_conf,
                                                        &ext_ctx, extensions,
                                                        x509ss)) {
            ALOGE("Error Loading extension section %s", extensions);
            goto end;
        }

        i = do_X509_sign(x509ss, pkey, digest, sigopts);
        if (!i) {
            ERR_print_errors_aloge();
            goto end;
        }
    }


    out = BIO_new(BIO_s_mem());
    if (isReq) {
        PEM_write_bio_X509_REQ(out, req);
    } else {
        PEM_write_bio_X509(out, x509ss);
    }
    outLen = BIO_ctrl_pending(out);
    outStr = static_cast<char *>(malloc(outLen + 1));
    BIO_read(out, outStr, outLen);
    BIO_free_all(out);
    ALOGI("%s", outStr);
    ALOGV("%s", outStr + 300);


    ret = 0;

    end:
    if (ret) {
        ERR_print_errors_aloge();
    }
    BIO_free(addext_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(genctx);
    sk_OPENSSL_STRING_free(pkeyopts);
    sk_OPENSSL_STRING_free(sigopts);
    lh_OPENSSL_STRING_free(addexts);
    OPENSSL_free(keyalgstr);
    X509_REQ_free(req);
    X509_free(x509ss);
    ASN1_INTEGER_free(serial);
    return ret;
}

static int make_REQ(X509_REQ *req, EVP_PKEY *pkey, int attribs, unsigned long chtype, CONF *req_conf) {
    int ret = 0, i;
    char no_prompt = 0;
    STACK_OF(CONF_VALUE) *dn_sk, *attr_sk = NULL;
    char *tmp, *dn_sect, *attr_sect;

    tmp = NCONF_get_string(req_conf, SECTION, PROMPT);
    if (tmp == NULL)
        ERR_clear_error();
    if ((tmp != NULL) && strcmp(tmp, "no") == 0)
        no_prompt = 1;

    dn_sect = NCONF_get_string(req_conf, SECTION, DISTINGUISHED_NAME);
    if (dn_sect == NULL) {
        ALOGE("unable to find '%s' in config", DISTINGUISHED_NAME);
        goto err;
    }
    dn_sk = NCONF_get_section(req_conf, dn_sect);
    if (dn_sk == NULL) {
        ALOGE("unable to get '%s' section", dn_sect);
        goto err;
    }

    attr_sect = NCONF_get_string(req_conf, SECTION, ATTRIBUTES);
    if (attr_sect == NULL) {
        ERR_clear_error();
        attr_sk = NULL;
    } else {
        attr_sk = NCONF_get_section(req_conf, attr_sect);
        if (attr_sk == NULL) {
            ALOGE("unable to get '%s' section", attr_sect);
            goto err;
        }
    }

    /* setup version number */
    if (!X509_REQ_set_version(req, 0L))
        goto err;               /* version 1 */

    i = provideInfo(req, chtype);

    if (!i)
        goto err;

    if (!X509_REQ_set_pubkey(req, pkey))
        goto err;

    ret = 1;
    err:
    return ret;
}

int set_cert_times(X509 *x, const char *startdate, const char *enddate, int days) {
    if (startdate == NULL || strcmp(startdate, "today") == 0) {
        if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
            return 0;
    } else {
        if (!ASN1_TIME_set_string_X509(X509_getm_notBefore(x), startdate))
            return 0;
    }
    if (enddate == NULL) {
        if (X509_time_adj_ex(X509_getm_notAfter(x), days, 0, NULL)
            == NULL)
            return 0;
    } else if (!ASN1_TIME_set_string_X509(X509_getm_notAfter(x), enddate)) {
        return 0;
    }
    return 1;
}


/*
 * Parse message digest name, put it in *EVP_MD; return 0 on failure, else 1.
 */
int opt_md(const char *name, const EVP_MD **mdp) {
    *mdp = EVP_get_digestbyname(name);
    if (*mdp != NULL)
        return 1;

    return 0;
}

CONF *app_load_config() {
    BIO *in;
    CONF *conf;
    int i;
    long errorline = -1;

    in = BIO_new(BIO_s_mem());
    BIO_write(in, REQ_CONFIG, sizeof(REQ_CONFIG));


    conf = NCONF_new(NULL);
    i = NCONF_load_bio(conf, in, &errorline);
    BIO_free_all(in);

    if (i > 0)
        return conf;

    if (errorline <= 0) {
        ALOGE("config Can't load ");
    } else {
        ALOGE("config Error on line %ld of ", errorline);
    }

    return NULL;
}

int do_X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md,
                 STACK_OF(OPENSSL_STRING) *sigopts) {
    int rv;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();

    rv = do_sign_init(mctx, pkey, md, sigopts);
    if (rv > 0)
        rv = X509_sign_ctx(x, mctx);
    EVP_MD_CTX_free(mctx);
    return rv > 0 ? 1 : 0;
}

static int do_sign_init(EVP_MD_CTX *ctx, EVP_PKEY *pkey,
                        const EVP_MD *md, STACK_OF(OPENSSL_STRING) *sigopts) {
    EVP_PKEY_CTX *pkctx = NULL;
    int i, def_nid;

    if (ctx == NULL)
        return 0;
    /*
     * EVP_PKEY_get_default_digest_nid() returns 2 if the digest is mandatory
     * for this algorithm.
     */
    if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) == 2
        && def_nid == NID_undef) {
        /* The signing algorithm requires there to be no digest */
        md = NULL;
    }
    if (!EVP_DigestSignInit(ctx, &pkctx, md, NULL, pkey))
        return 0;
    for (i = 0; i < sk_OPENSSL_STRING_num(sigopts); i++) {
        char *sigopt = sk_OPENSSL_STRING_value(sigopts, i);
        if (pkey_ctrl_string(pkctx, sigopt) <= 0) {
            ALOGE("parameter error \"%s\"\n", sigopt);
            ERR_print_errors_aloge();
            return 0;
        }
    }
    return 1;
}


int pkey_ctrl_string(EVP_PKEY_CTX *ctx, const char *value) {
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = OPENSSL_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}

int provideInfo(X509_REQ *req, unsigned long chtype) {
    X509_NAME *subj;
    subj = X509_REQ_get_subject_name(req);

    const unsigned char *countryName = reinterpret_cast<const unsigned char *>("CN\n");
    const unsigned char *stateOrProvinceName = reinterpret_cast<const unsigned char *>("Hangzhou\n");
    const unsigned char *localityName = reinterpret_cast<const unsigned char *>("None\n");
    const unsigned char *organizationName = reinterpret_cast<const unsigned char *>("YZ\n");
    const unsigned char *commonName = reinterpret_cast<const unsigned char *>("root\n");
    const unsigned char *emailAddress = reinterpret_cast<const unsigned char *>("guess@cc.cc\n");


    X509_NAME_add_entry_by_txt(subj, "countryName", chtype, countryName, sizeof(countryName), -1, 0);
    X509_NAME_add_entry_by_txt(subj, "stateOrProvinceName", chtype, stateOrProvinceName, sizeof(stateOrProvinceName), -1, 0);
    X509_NAME_add_entry_by_txt(subj, "localityName", chtype, localityName, sizeof(localityName), -1, 0);
    X509_NAME_add_entry_by_txt(subj, "organizationName", chtype, organizationName, sizeof(organizationName), -1, 0);
    X509_NAME_add_entry_by_txt(subj, "commonName", chtype, commonName, sizeof(commonName), -1, 0);
    X509_NAME_add_entry_by_txt(subj, "emailAddress", chtype, emailAddress, sizeof(emailAddress), -1, 0);

    return 1;
}


