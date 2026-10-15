// Copyright 2026 Batuhan Küçük
// SPDX-License-Identifier: Apache-2.0

#include <packetsail/proxy_config.hpp>

namespace packetsail {

bool is_valid_proxy_config(const ProxyConfig& config) {
    if (config.listen_address.empty()) {
        return false;
    }

    if (config.listen_port == 0) {
        return false;
    }

    return true;
}

} // namespace packetsail
