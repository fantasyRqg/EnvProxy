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
            src/main/cpp/ip/IpPackage.h
            src/main/cpp/ip/ip4.cpp
            src/main/cpp/ip/ip6.cpp
            src/main/cpp/ip/IpPackageFactory.cpp
            src/main/cpp/ip/IpPackage.cpp
            src/main/cpp/protocol/Icmp.cpp
            src/main/cpp/protocol/Tcp.cpp
            src/main/cpp/protocol/Udp.cpp
            src/main/cpp/protocol/Protocol.cpp
            src/main/cpp/protocol/ProtocolFactory.cpp
            src/main/cpp/task/Task.cpp
            src/main/cpp/task/TaskDNS.cpp
            src/main/cpp/task/TaskHttp.cpp
            src/main/cpp/task/TaskHttps.cpp
            src/main/cpp/task/TaskICMP.cpp
            src/main/cpp/task/TaskTCP.cpp
            src/main/cpp/task/TaskUDP.cpp
            src/main/cpp/task/TaskFactory.cpp
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