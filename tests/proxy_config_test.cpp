// Copyright 2026 Batuhan Küçük
// SPDX-License-Identifier: Apache-2.0

#include <packetsail/proxy_config.hpp>
#include <iostream>

int main() {
    const packetsail::ProxyConfig default_config;
    if (!packetsail::is_valid_proxy_config(default_config)) {
        std::cerr << "Default proxy configuration should be valid\n";
        return 1;
    }

    packetsail::ProxyConfig empty_address_config;
    empty_address_config.listen_address = "";
    if (packetsail::is_valid_proxy_config(empty_address_config)) {
        std::cerr << "Empty listen address should be invalid\n";
        return 1;
    }

    packetsail::ProxyConfig zero_port_config;
    zero_port_config.listen_port = 0;
    if (packetsail::is_valid_proxy_config(zero_port_config)) {
        std::cerr << "Zero listen port should be invalid\n";
        return 1;
    }

    packetsail::ProxyConfig invalid_config;
    invalid_config.listen_address = "";
    invalid_config.listen_port = 0;
    if (packetsail::is_valid_proxy_config(invalid_config)) {
        std::cerr << "Invalid proxy configuration should be rejected\n";
        return 1;
    }

    return 0;
}
