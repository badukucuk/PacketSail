#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace packetsail {

std::vector<std::uint8_t> split_tls_record(std::span<const std::uint8_t> record, std::size_t split_position);

}
