#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace packetsail {

// Splits a single TLS handshake record into two records without altering the fragment bytes.
// The split position is relative to the fragment.
// Throws std::invalid_argument for an invalid record or split position.
std::vector<std::uint8_t> split_tls_record(std::span<const std::uint8_t> record, std::size_t split_position);

}
