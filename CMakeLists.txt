cmake_minimum_required(VERSION 2.8)
project(rdpproxy)
set(CMAKE_CXX_COMPILER "clang++-10")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++")
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fcoroutines-ts --stdlib=libc++ -Xclang")
add_executable(
    rdpproxy
    src/main.cc
    src/server.cc
    src/session.cc
    src/config.cc
    src/auth.cc
)
find_package(Boost 1.71 COMPONENTS system REQUIRED)
find_package(OpenSSL REQUIRED)
include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS} ${BOTAN_INCLUDE_DIR} include vendor)
target_link_libraries(rdpproxy ${Boost_SYSTEM_LIBRARY} ${OPENSSL_LIBRARIES} pthread)
