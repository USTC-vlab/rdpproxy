#include "server.h"
#include "session.h"
#include "config.h"

using namespace std;
using boost::asio::ip::tcp;
using uds = boost::asio::local::stream_protocol; // UDS = Unix Domain Socket

extern Configuration configuration;

RDPProxyServer::RDPProxyServer() {
    tcp_acceptor = make_unique<tcp::acceptor>(ioc,
        tcp::endpoint(tcp::v6(), configuration.port));
    boost::asio::co_spawn(ioc, [this] { return accept_tcp(); }, boost::asio::detached);
}

void RDPProxyServer::run() {
    ioc.run();
}

boost::asio::awaitable<void> RDPProxyServer::accept_tcp() {
    while (true) {
        try {
            tcp::socket socket = co_await tcp_acceptor->async_accept(boost::asio::use_awaitable);
            auto session = make_shared<Session>(ioc, socket);
            session->start();
        } catch(...) {
            continue;
        }
    }
}