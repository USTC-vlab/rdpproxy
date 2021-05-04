#pragma once
#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>
#include <ctime>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

class Session: public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::io_context &ioc_, boost::asio::ip::tcp::socket &socket);
    void start();
    void close();
private:
    using HandshakeResult = std::tuple<bool, bool, std::string>; // success, redirection, token
    boost::asio::awaitable<void> handle();
    boost::asio::awaitable<HandshakeResult> handshake(std::vector<uint8_t> &cr_pdu);
    boost::asio::awaitable<bool> read_x224_cr_pdu(std::string &cookie, std::vector<uint8_t> &buffer);
    boost::asio::awaitable<void> handle_up_to_down();
    boost::asio::awaitable<void> handle_down_to_up();
    boost::asio::io_context &ioc;
    boost::asio::ip::tcp::socket upstream_socket;
    boost::asio::ip::tcp::socket downstream_socket;
    std::string ip;
    bool has_closed;
};