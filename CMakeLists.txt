cmake_minimum_required(VERSION 3.8)
project(rdpproxy)
set(CMAKE_CXX_STANDARD 20)
option(STATIC "Statically link" OFF)
if (STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -lpthread")
endif()
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fcoroutines")
add_executable(
    rdpproxy
    src/main.cc
    src/server.cc
    src/session.cc
    src/config.cc
    src/auth.cc
)
if (STATIC)
    set(Boost_USE_STATIC_LIBS ON)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
endif()
find_package(Boost 1.74 COMPONENTS system REQUIRED)
find_package(OpenSSL REQUIRED)
include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS} include vendor)
target_link_libraries(rdpproxy ${Boost_SYSTEM_LIBRARY} ${OPENSSL_LIBRARIES} pthread)
if (STATIC)
    target_link_libraries(rdpproxy pthread)
endif()
