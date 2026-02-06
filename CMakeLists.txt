cmake_minimum_required(VERSION 3.26)

project(
        tschrou
        VERSION 0.1.0
        DESCRIPTION "DHT"
        LANGUAGES CXX
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)

# Collect sources and headers
file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/*.cpp"
        "${PROJECT_SOURCE_DIR}/src/*.cxx"
        "${PROJECT_SOURCE_DIR}/src/*.cc"
)

file(GLOB_RECURSE PROJECT_HEADERS CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/*.h"
        "${PROJECT_SOURCE_DIR}/src/*.hpp"
        "${PROJECT_SOURCE_DIR}/src/*.hh"
)

add_executable(${PROJECT_NAME}
        ${PROJECT_SOURCES}
        ${PROJECT_HEADERS}
        src/node/node.h
        src/node/node.cc
        src/types/types.h
        src/net/tcp_server.h
        src/protocol/message.cc
        src/util/hash.cc
        src/util/hash.h
        src/node/fingertable.h
        src/node/fingertable.cc
        src/node/fingertable.h
        src/node/storage.h
        src/node/storage.cc
)

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_23)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_EXTENSIONS OFF)

target_include_directories(${PROJECT_NAME} PRIVATE "${PROJECT_SOURCE_DIR}/src")
target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /permissive- /Zc:preprocessor /utf-8)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

source_group(TREE "${PROJECT_SOURCE_DIR}" FILES ${PROJECT_SOURCES} ${PROJECT_HEADERS})