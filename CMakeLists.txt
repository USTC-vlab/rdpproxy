cmake_minimum_required(VERSION 3.8)
project(rdpproxy)
set(CMAKE_CXX_STANDARD 20)
option(STATIC "Statically link" OFF)
if (STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -lpthread")
endif()
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -fcoroutines")
add_custom_command(OUTPUT font.o
  COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && ld -r -b binary -o ${CMAKE_CURRENT_BINARY_DIR}/font.o src/font
  COMMAND objcopy --rename-section .data=.rodata,alloc,load,readonly,data,contents ${CMAKE_CURRENT_BINARY_DIR}/font.o ${CMAKE_CURRENT_BINARY_DIR}/font.o)
add_library(font STATIC font.o)
set_source_files_properties(font.o PROPERTIES EXTERNAL_OBJECT true GENERATED true)
set_target_properties(font PROPERTIES LINKER_LANGUAGE C)
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
find_package(PkgConfig REQUIRED)
pkg_check_modules(PACKAGES REQUIRED freerdp2 freerdp-server2 winpr2 xkbcommon vterm)
include_directories(${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS} ${PACKAGES_INCLUDE_DIRS} include vendor)
target_link_libraries(rdpproxy ${Boost_SYSTEM_LIBRARY} ${OPENSSL_LIBRARIES} ${PACKAGES_LINK_LIBRARIES} pthread font)
if (STATIC)
    target_link_libraries(rdpproxy pthread)
endif()
