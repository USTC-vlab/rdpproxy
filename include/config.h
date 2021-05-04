#pragma once
#include <set>
#include <vector>
#include <string>

struct Configuration {
    std::string api_url;
    std::string api_host;
    std::string api_port;
    std::string api_path;
    //std::string cert_chain_file;
    //std::string private_key_file;
    //std::string dhparam_file;
    uint16_t port;
    uint32_t threads;
};

bool load_configuration(const std::string &filename, Configuration &config);