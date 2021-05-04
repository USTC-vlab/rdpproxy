#pragma once
#include <memory>
#include <vector>
#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

class RDPProxyServer {
public:
    RDPProxyServer();
    void run();
private:
    boost::asio::awaitable<void> accept_tcp();
    boost::asio::io_context ioc;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> tcp_acceptor;
};