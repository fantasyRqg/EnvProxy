//
// Created by Rqg on 24/04/2018.
//

#include "Session.h"

Session::Session() : next(nullptr), prev(nullptr) {

}

Session::~Session() {

}


uint8_t *
Session::onTunDown(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size) {
    *_out_size = _in_size;
    return _in_data;
}

uint8_t *
Session::onTunUp(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size) {
    *_out_size = _in_size;
    return _in_data;
}

uint8_t *
Session::onSocketDown(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size) {
    *_out_size = _in_size;
    return _in_data;
}

uint8_t *
Session::onSocketUp(ProxyContext *ctx, uint8_t *_in_data, size_t _in_size, size_t *_out_size) {
    *_out_size = _in_size;
    return _in_data;
}
