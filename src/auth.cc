#include <string>
#include <iostream>
#include "nlohmann/json.hpp"
#include "auth.h"
#include "config.h"

using namespace std;

using boost::asio::ip::tcp;
namespace beast = boost::beast;
using json = nlohmann::json;

extern Configuration configuration;

boost::asio::awaitable<bool> auth(const string &token, string &username,
    string &ip, uint16_t &port, boost::asio::io_context &ioc) {
    beast::http::request<beast::http::string_body> http_req;
    beast::http::response<beast::http::string_body> http_res;
    tcp::socket http_socket(ioc);
    http_req.version(11);
    http_req.method(beast::http::verb::post);
    http_req.target(configuration.api_path);
    http_req.set("Host", configuration.api_host);
    http_req.set("Content-Type", "application/json");
    string body_str;
    try {
        json body;
        body["token"] = token;
        body_str = body.dump();
    } catch (json::exception &e) {
        co_return false;
    }
    http_req.body() = body_str;
    http_req.content_length(body_str.length());
    beast::flat_buffer buffer_http;
    tcp::resolver resolver(ioc);
    try {
        tcp::resolver::results_type res = co_await resolver.async_resolve(configuration.api_host,
            configuration.api_port, boost::asio::use_awaitable);
        co_await boost::asio::async_connect(http_socket,
            res, boost::asio::use_awaitable);
        co_await beast::http::async_write(http_socket, http_req, boost::asio::use_awaitable);
        size_t length = co_await beast::http::async_read(http_socket,
            buffer_http, http_res, boost::asio::use_awaitable);
        boost::system::error_code ec;
        http_socket.shutdown(tcp::socket::shutdown_both, ec);
        http_socket.close();
    } catch (std::exception &e) {
        co_return false;
    }
    try {
        json body = json::parse(http_res.body());
        string status = body["status"].get<string>();
        if (status != "ok") {
            co_return false;
        }
        ip = body["ip"].get<string>();
        port = body["port"].get<uint16_t>();
        auto it = body.find("username");
        if (it != body.end()) {
            username = body["username"].get<string>();
        }
    } catch (json::exception &e) {
        co_return false;
    }
    co_return true;
}

boost::asio::awaitable<bool> auth(const string &username, const string &password,
    string &ip, string &host_username, string &token, boost::asio::io_context &ioc) {
    beast::http::request<beast::http::string_body> http_req;
    beast::http::response<beast::http::string_body> http_res;
    tcp::socket http_socket(ioc);
    http_req.version(11);
    http_req.method(beast::http::verb::post);
    http_req.target(configuration.api_path);
    http_req.set("Host", configuration.api_host);
    http_req.set("Content-Type", "application/json");
    string body_str;
    try {
        json body;
        body["username"] = username;
        body["password"] = password;
        body_str = body.dump();
    } catch (json::exception &e) {
        co_return false;
    }
    http_req.body() = body_str;
    http_req.content_length(body_str.length());
    beast::flat_buffer buffer_http;
    tcp::resolver resolver(ioc);
    try {
        tcp::resolver::results_type res = co_await resolver.async_resolve(configuration.api_host,
            configuration.api_port, boost::asio::use_awaitable);
        co_await boost::asio::async_connect(http_socket,
            res, boost::asio::use_awaitable);
        co_await beast::http::async_write(http_socket, http_req, boost::asio::use_awaitable);
        size_t length = co_await beast::http::async_read(http_socket,
            buffer_http, http_res, boost::asio::use_awaitable);
        boost::system::error_code ec;
        http_socket.shutdown(tcp::socket::shutdown_both, ec);
        http_socket.close();
    } catch (std::exception &e) {
        co_return false;
    }
    try {
        json body = json::parse(http_res.body());
        string status = body["status"].get<string>();
        if (status != "ok") {
            co_return false;
        }
        auto it = body.find("username");
        if (it != body.end()) {
            host_username = body["username"].get<string>();
        }
        it = body.find("ip");
        if (it != body.end()) {
            ip = body["ip"].get<string>();
        }
        it = body.find("token");
        if (it != body.end()) {
            token = body["token"].get<string>();
        }
    } catch (json::exception &e) {
        co_return false;
    }
    co_return true;
}