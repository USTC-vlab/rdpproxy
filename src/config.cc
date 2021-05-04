#include <string>
#include <fstream>
#include <iostream>
#include "nlohmann/json.hpp"
#include "config.h"

using namespace std;
using json = nlohmann::json;

bool parse_url(string url, string &host, string &port, string &path) {
    if (url.length() <= 7) {
        return false;
    }
    if (url.substr(0, 7) != "http://") {
        return false;
    }
    url = url.substr(7);
    size_t pos = url.find(':');
    if (pos != string::npos) {
        host = url.substr(0, pos);
        url = url.substr(pos + 1);
        pos = url.find('/');
        if (pos == string::npos) {
            port = url;
            path = "/";
        } else {
            port = url.substr(0, pos);
            path = url.substr(pos);
        }
    } else {
        pos = url.find('/');
        if (pos == string::npos) {
            host = url;
            port = "80";
            path = "/";
        } else {
            host = url.substr(0, pos);
            port = "80";
            path = url.substr(pos);
        }
    }
    return true;
}

bool load_configuration(const string &filename, Configuration &config) {
    try {
        ifstream ifs(filename);
        if (!ifs) {
            cerr << "Cannot open configuration file.\n";
            return false;
        }
        json config_json = json::parse(ifs);
        config.port = config_json["port"].get<uint16_t>();
        config.api_url = config_json["api"].get<string>();
        if (!parse_url(config.api_url, config.api_host, config.api_port, config.api_path)) {
            cerr << "Cannot parse configuration file: invalid API URL.\n";
            return false;
        }
    } catch (json::exception &e) {
        cerr << "Cannot parse configuration file: invalid JSON file.\n";
        return false;
    }
    return true;
}