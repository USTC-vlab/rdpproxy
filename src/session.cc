#include <iostream>
#include <cstring>
#include "util.h"
#include "session.h"
#include "config.h"
#include "auth.h"

using namespace std;
using boost::asio::ip::tcp;

static const tuple<bool, bool, string, ssize_t> HandshakeError(false, false, "", 0);

extern Configuration configuration;

Session::Session(boost::asio::io_context &ioc_, tcp::socket &socket)
    : ioc(ioc_), downstream_socket(move(socket)), upstream_socket(ioc), has_closed(false),
      has_ssl_handshaked(false) {
    downstream_socket.set_option(tcp::no_delay(true));
    downstream_socket.set_option(boost::asio::socket_base::keep_alive(true));
    ip = downstream_socket.remote_endpoint().address().to_string();
}

void Session::start() {
    boost::asio::co_spawn(ioc.get_executor(),
        [self = shared_from_this()] {
            return self->handle();
        }, boost::asio::detached
    );
}

void Session::close() {
    if (has_closed) {
        return;
    }
    if (downstream_socket.is_open()) {
        boost::system::error_code ec;
        downstream_socket.shutdown(tcp::socket::shutdown_both, ec);
        downstream_socket.close();
    }
    if (upstream_socket.is_open()) {
        boost::system::error_code ec;
        upstream_socket.shutdown(tcp::socket::shutdown_both, ec);
        upstream_socket.close();
    }
    has_closed = true;
}

boost::asio::awaitable<void> Session::handle() {
    try {
        bool success, is_redirection;
        vector<uint8_t> cr_pdu;
        string token;
        size_t neg_offset;
        tie(success, is_redirection, token, neg_offset) = co_await handshake(cr_pdu);
        if (!success) {
            close();
            co_return;
        }
        if (is_redirection) {
            string username;
            string ip;
            uint16_t port;
            if (!co_await auth(token, username, ip, port, ioc)) {
                close();
                co_return;
            }
            co_await upstream_socket.async_connect(
                tcp::endpoint(boost::asio::ip::address::from_string(ip), port),
                boost::asio::use_awaitable);
            upstream_socket.set_option(tcp::no_delay(true));
            //co_await ASYNC_WRITE(upstream_socket, cr_pdu);
            boost::asio::co_spawn(ioc.get_executor(),
                [self = shared_from_this(), this] {
                    return handle_up_to_down();
                }, boost::asio::detached
            );
            boost::asio::co_spawn(ioc.get_executor(),
                [self = shared_from_this(), this] {
                    return handle_down_to_up();
                }, boost::asio::detached
            );
        }
    } catch (std::exception &e) {
        close();
    }
    co_return;
}

boost::asio::awaitable<Session::HandshakeResult> Session::handshake(vector<uint8_t> &cr_pdu) {
    string cookie;
    vector<uint8_t> buffer;
    ssize_t neg_offset;
    if (!co_await peak_x224_cr_pdu(cookie, buffer, neg_offset)) {
        co_return HandshakeError;
    }
    bool is_redirection = false;
    string token;
    string prefix("Cookie: msts=");
    if (str_startswith(cookie, prefix)) {
        is_redirection = true;
        size_t old_size = buffer.size();
        size_t cookie_size = cookie.size() + 2;
        cr_pdu.resize(old_size - cookie_size);
        uint8_t *p = cr_pdu.data();
        memcpy(p, buffer.data(), 11);
        ssize_t remain_size = old_size - 11 - cookie_size;
        if (remain_size > 0) {
            memcpy(cr_pdu.data() + 11, buffer.data() + 11 + cookie_size, remain_size);
        }
        store_u16be(p + 2, old_size - cookie_size);
        p[4] = old_size - cookie_size - 5;
        token = cookie.substr(prefix.length());
        neg_offset -= cookie_size;
    } else {
        cr_pdu = std::move(buffer);
    }
    co_return HandshakeResult(true, is_redirection, token, neg_offset);
}

boost::asio::awaitable<bool> Session::read_x224_cr_pdu(string &cookie, vector<uint8_t> &buffer, ssize_t &neg_offset) {
    uint8_t tpkt_version = co_await read_u16(downstream_socket, buffer);
    if (tpkt_version != 0x03) {
        co_return false;
    }
    size_t tpkt_size = co_await read_u16be(downstream_socket, buffer);
    uint8_t length_indicator = co_await read_u8(downstream_socket, buffer);
    if (tpkt_size != length_indicator + 5) {
        co_return false;
    }
    uint8_t cr_cdt = co_await read_u8(downstream_socket, buffer);
    if (cr_cdt != 0xe0) {
        co_return false;
    }
    uint16_t dst_ref = co_await read_u16(downstream_socket, buffer);
    if (dst_ref != 0) {
        co_return false;
    }
    uint16_t src_ref = co_await read_u16(downstream_socket, buffer);
    uint8_t class_option = co_await read_u8(downstream_socket, buffer);
    if ((class_option & 0xfc) != 0) {
        co_return false;
    }
    size_t size = length_indicator - 6;
    uint8_t *p = co_await read_bytes(downstream_socket, buffer, size);
    size_t pos = search_crlf(p, size);
    if (pos != string::npos) {
        cookie = string((const char *)p, pos);
        neg_offset = p - buffer.data() + pos + 2;
    } else {
        neg_offset = p - buffer.data();
    }
    co_return true;
}

boost::asio::awaitable<bool> Session::peak_x224_cr_pdu(std::string &cookie, std::vector<uint8_t> &buffer, ssize_t &neg_offset) {
    uint8_t *p = co_await peek_bytes(downstream_socket, buffer, 4);
    uint8_t tpkt_version = p[0];
    if (tpkt_version != 0x03) {
        co_return false;
    }
    uint16_t tpkt_size = load_u16be(p + 2);
    p = co_await peek_bytes(downstream_socket, buffer, tpkt_size);
    uint8_t length_indicator = p[4];
    uint8_t cr_cdt = p[5];
    uint16_t dst_ref = load_u16(p + 6);
    uint16_t src_ref = load_u16(p + 8);
    uint8_t class_option = p[10];
    if (tpkt_size - 5 != length_indicator || cr_cdt != 0xe0 || dst_ref != 0 || (class_option & 0xfc) != 0) {
        co_return false;
    }
    p += 11;
    size_t pos = search_crlf(p, buffer.size() - 11);
    if (pos != string::npos) {
        cookie = string((const char *)p, pos);
        neg_offset = p - buffer.data() + pos + 2;
    } else {
        neg_offset = p - buffer.data();
    }
    co_return true;
}

boost::asio::awaitable<void> Session::handle_up_to_down() {
    const size_t BufferSize = 65536;
    vector<uint8_t> buffer(BufferSize);
    try {
        while (true) {
            size_t size = co_await ASYNC_READ_SOME(upstream_socket, buffer, BufferSize);
            co_await ASYNC_WRITE(downstream_socket, buffer, size);
        }
    } catch (std::exception &e) {
        close();
    }
    co_return;
}

boost::asio::awaitable<void> Session::handle_down_to_up() {
    const size_t BufferSize = 65536;
    vector<uint8_t> buffer(BufferSize);
    try {
        while (true) {
            size_t size = co_await ASYNC_READ_SOME(downstream_socket, buffer, BufferSize);
            co_await ASYNC_WRITE(upstream_socket, buffer, size);
        }
    } catch (std::exception &e) {
        close();
    }
    co_return;
}