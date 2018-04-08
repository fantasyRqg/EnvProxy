cmake_minimum_required(VERSION 3.4.1)


add_library(libProxy
            SHARED

            src/main/cpp/libProxy.cpp
            src/main/cpp/proxyEngine.cpp
            )

find_library(log-lib log)

target_link_libraries( libProxy

                       ${log-lib} )