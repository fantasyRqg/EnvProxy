cmake_minimum_required(VERSION 3.4.1)

set(OPENSSL_DIR
            ${CMAKE_SOURCE_DIR}/../openssl)

# add the open ssl crypto lib
add_library(libcrypto STATIC IMPORTED)
set_target_properties(libcrypto PROPERTIES IMPORTED_LOCATION
    ${OPENSSL_DIR}/${ANDROID_ABI}/lib/libcrypto.a)

# add the open ssl ssl lib
add_library(libssl STATIC IMPORTED)
set_target_properties(libssl PROPERTIES IMPORTED_LOCATION
    ${OPENSSL_DIR}/${ANDROID_ABI}/lib/libssl.a)



add_library(libProxy
            SHARED

            src/main/cpp/libProxy.cpp
            src/main/cpp/util.cpp
            src/main/cpp/test.cpp
            src/main/cpp/BufferPool.cpp
            src/main/cpp/proxyTypes.cpp
            src/main/cpp/proxyEngine.cpp
            src/main/cpp/ip/Ip4Handler.cpp
            src/main/cpp/ip/Ip6Handler.cpp
            src/main/cpp/ip/IpPackageFactory.cpp
            src/main/cpp/ip/IpHandler.cpp
            src/main/cpp/transport/IcmpHandler.cpp
            src/main/cpp/transport/TcpHandler.cpp
            src/main/cpp/transport/UdpHandler.cpp
            src/main/cpp/transport/TransportHandler.cpp
            src/main/cpp/transport/TransportFactory.cpp
            src/main/cpp/session/Session.cpp
            src/main/cpp/session/DnsSession.cpp
            src/main/cpp/session/HttpSession.cpp
            src/main/cpp/session/TlsSession.cpp
            src/main/cpp/session/IcmpSession.cpp
            src/main/cpp/session/TcpSession.cpp
            src/main/cpp/session/UdpSession.cpp
            src/main/cpp/session/SessionFactory.cpp
            )

# add to target_include_directories
target_include_directories(libProxy PRIVATE
                ${OPENSSL_DIR}/${ANDROID_ABI}/include)

find_library(log-lib log)

target_link_libraries( libProxy

                        libssl
                        libcrypto
                       # ${OPENSSL_LIBRARIES}
                       ${log-lib} )