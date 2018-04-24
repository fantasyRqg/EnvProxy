cmake_minimum_required(VERSION 3.4.1)

set(OPENSSL_DIR
            ${CMAKE_SOURCE_DIR}/../openssl-1.1.1-pre5/out/)

# add the open ssl crypto lib
add_library(libcrypto STATIC IMPORTED)
set_target_properties(libcrypto PROPERTIES IMPORTED_LOCATION
    ${OPENSSL_DIR}/lib/libcrypto.a)

# add the open ssl ssl lib
add_library(libssl STATIC IMPORTED)
set_target_properties(libssl PROPERTIES IMPORTED_LOCATION
    ${OPENSSL_DIR}/lib/libssl.a)



add_library(libProxy
            SHARED

            src/main/cpp/libProxy.cpp
            src/main/cpp/proxyEngine.cpp
            src/main/cpp/ip/ip.cpp
            src/main/cpp/ip/ip4.cpp
            src/main/cpp/ip/ip6.cpp
            src/main/cpp/protocol/icmp.cpp
            src/main/cpp/protocol/tcp.cpp
            src/main/cpp/protocol/udp.cpp
            )

# add to target_include_directories
target_include_directories(libProxy PRIVATE
                ${OPENSSL_DIR}/include)

find_library(log-lib log)

target_link_libraries( libProxy

                        libssl
                        libcrypto
                       # ${OPENSSL_LIBRARIES}
                       ${log-lib} )