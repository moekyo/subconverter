cmake_minimum_required(VERSION 3.10)
project(reality_roundtrip LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")
include_directories(../include)
set(BUILD_STATIC_LIBRARY ON CACHE BOOL "Build the production conversion library" FORCE)
add_subdirectory(.. subconverter)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAML_CPP yaml-cpp REQUIRED)
add_executable(reality-convert reality-convert.cpp)
target_compile_definitions(reality-convert PRIVATE NO_JS_RUNTIME NO_WEBGET)
target_include_directories(reality-convert PRIVATE ${RAPIDJSON_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS})
target_link_libraries(reality-convert PRIVATE subconverter)
add_executable(protocol-convert protocol-convert.cpp)
target_compile_definitions(protocol-convert PRIVATE NO_JS_RUNTIME NO_WEBGET)
target_include_directories(protocol-convert PRIVATE ${RAPIDJSON_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS})
target_link_libraries(protocol-convert PRIVATE subconverter)
add_executable(policy-contracts policy-contracts.cpp)
target_compile_definitions(policy-contracts PRIVATE NO_JS_RUNTIME NO_WEBGET)
target_include_directories(policy-contracts PRIVATE ${RAPIDJSON_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS})
target_link_libraries(policy-contracts PRIVATE subconverter)
add_executable(subscription-proxy-route subscription-proxy-route.cpp)
target_include_directories(subscription-proxy-route PRIVATE ../src)
target_compile_options(subscription-proxy-route PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-UNDEBUG>)

option(BUILD_FETCH_TESTS "Build the real-curl loopback regression driver" OFF)
if(BUILD_FETCH_TESTS)
    find_package(CURL REQUIRED)
    add_executable(fetch-contract-driver
        fetch-contract-driver.cpp
        ../src/handler/webget.cpp
        ../src/utils/file.cpp
        ../src/utils/string.cpp
        ../src/utils/urlencode.cpp
        ../src/utils/base64/base64.cpp
        ../src/utils/md5/md5.cpp)
    target_compile_definitions(fetch-contract-driver PRIVATE NO_JS_RUNTIME)
    target_include_directories(fetch-contract-driver PRIVATE ../src ${RAPIDJSON_INCLUDE_DIRS} ${YAML_CPP_INCLUDE_DIRS})
    target_link_libraries(fetch-contract-driver PRIVATE CURL::libcurl)
endif()
