cmake_minimum_required(VERSION 3.20)

project(cslol-patcher LANGUAGES C)

include(FetchContent)

cmake_policy(SET CMP0169 OLD)

FetchContent_Declare(
    openssl_headers
    GIT_REPOSITORY https://github.com/openssl/openssl.git
    GIT_TAG        ac3cef223a4c61d6bee34527b6d4c8c6432494a7 #OpenSSL_1_1_1m
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
)
FetchContent_GetProperties(openssl_headers)

FetchContent_Declare(
    curl_headers
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG        bfbde883af33397943df68a3ae01847a634d33bf #curl-7_78_0
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
)
FetchContent_GetProperties(openssl_headers)

if(NOT openssl_headers_POPULATED)
    FetchContent_Populate(openssl_headers)

    file(GLOB_RECURSE openssl_headers_HEADERS
       ${CMAKE_CURRENT_LIST_DIR}/include/crypto/*.h
       ${CMAKE_CURRENT_LIST_DIR}/include/openssl/*.h
       ${openssl_headers_SOURCE_DIR}/include/*.h
       ${openssl_headers_SOURCE_DIR}/crypto/*.h
       ${openssl_headers_SOURCE_DIR}/openssl/*.h
       ${openssl_headers_SOURCE_DIR}/e_os.h
    )

    add_library(openssl_headers INTERFACE ${openssl_HEADERS})

    file(GENERATE OUTPUT ${openssl_headers_BINARY_DIR}/include/openssl/opensslconf.h CONTENT "#include <openssl/opensslv.h>")
    target_sources(openssl_headers INTERFACE ${openssl_headers_BINARY_DIR}/include/openssl/opensslconf.h)

    target_include_directories(openssl_headers INTERFACE
        ${openssl_headers_BINARY_DIR}/include
        ${openssl_headers_SOURCE_DIR}/include
        ${openssl_headers_SOURCE_DIR}
    )
endif()

if (NOT curl_headers_POPULATED)
    FetchContent_Populate(curl_headers)

    file(GLOB_RECURSE curl_headers_HEADERS
       ${curl_headers_SOURCE_DIR}/include/*.h
       ${curl_headers_SOURCE_DIR}/lib/*.h
    )

    add_library(curl_headers INTERFACE ${curl_HEADERS})

    target_include_directories(curl_headers INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${curl_headers_SOURCE_DIR}/include
        ${curl_headers_SOURCE_DIR}/lib
    )
endif()
