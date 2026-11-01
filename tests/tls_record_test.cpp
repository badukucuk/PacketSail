#include "packetsail/tls_record.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cstddef>

bool rejects_invalid_record(const std::vector<std::uint8_t>& record) {
    try {
        packetsail::split_tls_record(record, 2);
    } catch (const std::invalid_argument&) {
        return true;
    }

    return false;
}

bool test_incomplete_header() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01
    };

    return rejects_invalid_record(record);
}

bool test_wrong_record_type() {
    const std::vector<std::uint8_t> record = {
        0x17, 0x03, 0x01, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    return rejects_invalid_record(record);
}

bool test_wrong_record_length() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x08,
        0x01, 0x02, 0x03, 0x04
    };

    return rejects_invalid_record(record);
}

bool test_successful_split() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    const std::vector<std::uint8_t> expected = {
        0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x02,
        0x16, 0x03, 0x01, 0x00, 0x02, 0x03, 0x04
    };

    const auto result = packetsail::split_tls_record(record, 2);

    return result == expected;
}

bool test_zero_split_position() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    try {
        packetsail::split_tls_record(record, 0);
    } catch (const std::invalid_argument&) {
        return true;
    }

    return false;
}

bool test_split_position_at_fragment_end() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    try {
        packetsail::split_tls_record(record, 4);
    } catch (const std::invalid_argument&) {
        return true;
    }

    return false;
}

bool test_large_fragment_split() {
    constexpr std::size_t first_length = 300;
    constexpr std::size_t second_length = 100;
    constexpr std::size_t fragment_length = first_length + second_length;

    std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x01, 0x90
    };

    record.insert(record.end(), fragment_length, 0xAB);

    const auto result = packetsail::split_tls_record(record, first_length);

    if (result.size() != record.size() + 5) {
        return false;
    }

    if (result[3] != 0x01 || result[4] != 0x2C) {
        return false;
    }

    const std::size_t second_header = 5 + first_length;

    if (result[second_header + 3] != 0x00 ||
        result[second_header + 4] != 0x64) {
        return false;
    }

    return true;
}

bool test_split_position_beyond_fragment() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    try {
        packetsail::split_tls_record(record, 5);
    } catch (const std::invalid_argument&) {
        return true;
    }

    return false;
}

bool test_fragment_data_preserved() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x06,
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60
    };

    const std::vector<std::uint8_t> expected = {
        0x16, 0x03, 0x01, 0x00, 0x02,
        0x10, 0x20,
        0x16, 0x03, 0x01, 0x00, 0x04,
        0x30, 0x40, 0x50, 0x60
    };

    const auto result = packetsail::split_tls_record(record, 2);

    return result == expected;
}

bool test_negative_split_position() {
    const std::vector<std::uint8_t> record = {
        0x16, 0x03, 0x01, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04
    };

    try {
        packetsail::split_tls_record(
            record,
            static_cast<std::size_t>(-1)
        );
    } catch (const std::invalid_argument&) {
        return true;
    }

    return false;
}

int main() {
    bool all_passed = true;

    if (test_incomplete_header()) {
        std::cout << "PASS: test_incomplete_header\n";
    } else {
        std::cerr << "FAIL: test_incomplete_header\n";
        all_passed = false;
    }

    if (test_wrong_record_type()) {
        std::cout << "PASS: test_wrong_record_type\n";
    } else {
        std::cerr << "FAIL: test_wrong_record_type\n";
        all_passed = false;
    }

    if (test_wrong_record_length()) {
        std::cout << "PASS: test_wrong_record_length\n";
    } else {
        std::cerr << "FAIL: test_wrong_record_length\n";
        all_passed = false;
    }

    if (test_successful_split()) {
        std::cout << "PASS: test_successful_split\n";
    } else {
        std::cerr << "FAIL: test_successful_split\n";
        all_passed = false;
    }

    if (test_zero_split_position()) {
        std::cout << "PASS: test_zero_split_position\n";
    } else {
        std::cerr << "FAIL: test_zero_split_position\n";
        all_passed = false;
    }

    if (test_split_position_at_fragment_end()) {
        std::cout << "PASS: test_split_position_at_fragment_end\n";
    } else {
        std::cerr << "FAIL: test_split_position_at_fragment_end\n";
        all_passed = false;
    }

    if (test_large_fragment_split()) {
        std::cout << "PASS: test_large_fragment_split\n";
    } else {
        std::cerr << "FAIL: test_large_fragment_split\n";
        all_passed = false;
    }

    if (test_split_position_beyond_fragment()) {
        std::cout << "PASS: test_split_position_beyond_fragment\n";
    } else {
        std::cerr << "FAIL: test_split_position_beyond_fragment\n";
        all_passed = false;
    }

    if (test_fragment_data_preserved()) {
        std::cout << "PASS: test_fragment_data_preserved\n";
    } else {
        std::cerr << "FAIL: test_fragment_data_preserved\n";
        all_passed = false;
    }

    if (test_negative_split_position()) {
        std::cout << "PASS: test_negative_split_position\n";
    } else {
        std::cerr << "FAIL: test_negative_split_position\n";
        all_passed = false;
    }

    return all_passed ? 0 : 1;
}
