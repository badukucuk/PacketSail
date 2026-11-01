#include <packetsail/tls_record.hpp>

#include <stdexcept>

namespace packetsail {

std::vector<std::uint8_t> split_tls_record(std::span<const std::uint8_t> record, std::size_t split_position) {
    constexpr std::size_t header_size = 5;

    if (record.size() < header_size) {
        throw std::invalid_argument("TLS record header is incomplete");
    }

    if (record[0] != 0x16) {
        throw std::invalid_argument("Expected a TLS handshake record");
    }

    const std::size_t fragment_length = (static_cast<std::size_t>(record[3]) << 8) | record[4];

    if (fragment_length != record.size() - header_size) {
        throw std::invalid_argument("TLS record length mismatch");
    }

    if (split_position == 0 || split_position >= fragment_length) {
        throw std::invalid_argument("Invalid TLS record split position");
    }

    const std::size_t second_length = fragment_length - split_position;

    std::vector<std::uint8_t> result;
    result.reserve(record.size() + header_size);

    // Write the first TLS record header.
    result.push_back(record[0]);
    result.push_back(record[1]);
    result.push_back(record[2]);
    result.push_back(static_cast<std::uint8_t>((split_position >> 8) & 0xFF));
    result.push_back(static_cast<std::uint8_t>(split_position & 0xFF));

    for (std::size_t i = 0; i < split_position; ++i) {
        result.push_back(record[header_size + i]);
    }

    // Write the second TLS record header.
    result.push_back(record[0]);
    result.push_back(record[1]);
    result.push_back(record[2]);
    result.push_back(static_cast<std::uint8_t>(second_length >> 8));
    result.push_back(static_cast<std::uint8_t>(second_length & 0xFF));

    for (std::size_t i = split_position; i < fragment_length; ++i) {
        result.push_back(record[header_size + i]);
    }

    return result;
}

}
