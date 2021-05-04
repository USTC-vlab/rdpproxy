#pragma once
#include <tuple>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

boost::asio::awaitable<bool> auth(const std::string &token, std::string &username,
    std::string &ip, uint16_t &port, boost::asio::io_context &ioc);