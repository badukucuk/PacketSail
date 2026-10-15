// Copyright 2026 Batuhan Küçük
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string>

namespace packetsail {

struct ProxyConfig {
    std::string listen_address = "127.0.0.1";
    std::uint16_t listen_port = 8080;
};

bool is_valid_proxy_config(const ProxyConfig& config);

} // namespace packetsail
