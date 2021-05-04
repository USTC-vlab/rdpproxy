#pragma once
#include <string>
#include <iostream>
#include <vector>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <inttypes.h>
#include <byteswap.h>

#define ASYNC_READ(s, ...) boost::asio::async_read((s), boost::asio::buffer(__VA_ARGS__), boost::asio::use_awaitable)
#define ASYNC_WRITE(s, ...) boost::asio::async_write((s), boost::asio::buffer(__VA_ARGS__), boost::asio::use_awaitable)
#define ASYNC_READ_SOME(s, ...) (s).async_read_some(boost::asio::buffer(__VA_ARGS__), boost::asio::use_awaitable)
#define WS_ASYNC_WRITE(s, ...) (s).async_write(boost::asio::buffer(__VA_ARGS__), boost::asio::use_awaitable)

inline void store_u32(void *addr, uint32_t val) {
    *(uint32_t *)addr = val;
}

inline uint32_t load_u32(const void *addr) {
    return *(const uint32_t *)addr;
}

inline void store_u32be(void *addr, uint32_t val) {
    *(uint32_t *)addr = bswap_32(val);
}

inline uint32_t load_u32be(const void *addr) {
    return bswap_32(*(const uint32_t *)addr);
}

template <class T>
inline T load(void *addr) {
    return *(T *)addr;
}

template <class T>
inline void store(void *addr, T val) {
    *(T *)addr = val;
}

inline void copy_u16(void *dst, const void *src) {
    *(uint16_t *)dst = *(uint16_t *)src;
}

inline void store_u16(void *addr, uint16_t val) {
    *(uint16_t *)addr = val;
}

inline uint16_t load_u16(const void *addr) {
    return *(const uint16_t *)addr;
}

inline void store_u16be(void *addr, uint16_t val) {
    *(uint16_t *)addr = bswap_16(val);
}

inline uint16_t load_u16be(const void *addr) {
    return bswap_16(*(const uint16_t *)addr);
}

inline uint8_t *expand_buffer(std::vector<uint8_t> &buffer, size_t length) {
    size_t buffer_size = buffer.size();
    buffer.resize(buffer_size + length);
    return buffer.data() + buffer_size;
}

inline void append_buffer(std::vector<uint8_t> &buffer, const std::vector<uint8_t> &data) {
    uint8_t *p = expand_buffer(buffer, data.size());
    memcpy(p, data.data(), data.size());
}

template <class T>
inline boost::asio::awaitable<uint8_t *> read_bytes(T &socket, std::vector<uint8_t> &buffer, size_t length) {
    uint8_t *p = expand_buffer(buffer, length);
    co_await ASYNC_READ(socket, p, length);
    co_return p;
}

template <class T>
inline boost::asio::awaitable<uint8_t> read_u8(T &socket, std::vector<uint8_t> &buffer) {
    uint8_t *p = expand_buffer(buffer, 1);
    co_await ASYNC_READ(socket, p, 1);
    co_return *p;
}

template <class T>
inline boost::asio::awaitable<uint16_t> read_u16(T &socket, std::vector<uint8_t> &buffer) {
    uint8_t *p = expand_buffer(buffer, 2);
    co_await ASYNC_READ(socket, p, 2);
    co_return load_u16(p);
}

template <class T>
inline boost::asio::awaitable<uint16_t> read_u16be(T &socket, std::vector<uint8_t> &buffer) {
    uint8_t *p = expand_buffer(buffer, 2);
    co_await ASYNC_READ(socket, p, 2);
    co_return load_u16be(p);
}

template <class T>
inline boost::asio::awaitable<uint32_t> read_u32(T &socket, std::vector<uint8_t> &buffer) {
    uint8_t *p = expand_buffer(buffer, 4);
    co_await ASYNC_READ(socket, p, 4);
    co_return load_u32(p);
}

template <class T>
inline boost::asio::awaitable<uint32_t> read_u32be(T &socket, std::vector<uint8_t> &buffer) {
    uint8_t *p = expand_buffer(buffer, 4);
    co_await ASYNC_READ(socket, p, 4);
    co_return load_u32be(p);
}

inline size_t search_crlf(const uint8_t *data, size_t size) {
    for (size_t i = 0; i + 1 < size; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            return i;
        }
    }
    return std::string::npos;
}

inline bool str_startswith(const std::string &s1, const std::string &s2) {
    return s1.length() >= s2.length() && s1.substr(0, s2.length()) == s2;
}