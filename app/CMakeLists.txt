cmake_minimum_required(VERSION 3.4.1)


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

find_library(log-lib log)

target_link_libraries( libProxy

                       ${log-lib} )