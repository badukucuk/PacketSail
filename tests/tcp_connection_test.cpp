#include "packetsail/socket_handle.hpp"
#include "packetsail/tcp_connection.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

bool test_send_all_empty_data() {
    return packetsail::send_all(-1, nullptr, 0);
}

bool test_socket_data_transfer() {
    int sockets[2];

    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
        return false;
    }

    packetsail::SocketHandle sender(sockets[0]);
    packetsail::SocketHandle receiver(sockets[1]);

    const std::array<std::uint8_t, 5> message = {
        0x10, 0x20, 0x30, 0x40, 0x50
    };

    if (!packetsail::send_all(
            sender.get(),
            message.data(),
            message.size()
        )) {
        return false;
    }

    std::array<std::uint8_t, 5> buffer{};

    std::size_t total_received = 0;

    while (total_received < buffer.size()) {
        const ssize_t received = packetsail::receive_data(
            receiver.get(),
            buffer.data() + total_received,
            buffer.size() - total_received
        );

        if (received <= 0) {
            return false;
        }

        total_received += static_cast<std::size_t>(received);
    }

    return buffer == message;
}

bool test_tcp_loopback_connection() {
    packetsail::SocketHandle server(::socket(AF_INET, SOCK_STREAM, 0));

    if (server.get() == -1) {
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(0);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::bind(
            server.get(),
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        ) == -1) {
        return false;
    }

    if (::listen(server.get(), 1) == -1) {
        return false;
    }

    socklen_t address_length = sizeof(address);

    if (::getsockname(
            server.get(),
            reinterpret_cast<sockaddr*>(&address),
            &address_length
        ) == -1) {
        return false;
    }

    packetsail::SocketHandle client(::socket(AF_INET, SOCK_STREAM, 0));

    if (client.get() == -1) {
        return false;
    }

    if (::connect(
            client.get(),
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        ) == -1) {
        return false;
    }

    packetsail::SocketHandle accepted(
        ::accept(server.get(), nullptr, nullptr)
    );

    if (accepted.get() == -1) {
        return false;
    }

    const std::array<std::uint8_t, 4> message = {
        0x10, 0x20, 0x30, 0x40
    };

    if (!packetsail::send_all(
            client.get(),
            message.data(),
            message.size()
        )) {
        return false;
    }

    std::array<std::uint8_t, 4> buffer{};
    std::size_t total_received = 0;

    while (total_received < buffer.size()) {
        const ssize_t received = packetsail::receive_data(
            accepted.get(),
            buffer.data() + total_received,
            buffer.size() - total_received
        );

        if (received <= 0) {
            return false;
        }

        total_received += static_cast<std::size_t>(received);
    }

    return buffer == message;
}

int main() {
    bool all_passed = true;

    if (test_send_all_empty_data()) {
        std::cout << "PASS: test_send_all_empty_data\n";
    } else {
        std::cerr << "FAIL: test_send_all_empty_data\n";
        all_passed = false;
    }

    if (test_socket_data_transfer()) {
        std::cout << "PASS: test_socket_data_transfer\n";
    } else {
        std::cerr << "FAIL: test_socket_data_transfer\n";
        all_passed = false;
    }

    if (test_tcp_loopback_connection()) {
        std::cout << "PASS: test_tcp_loopback_connection\n";
    } else {
        std::cerr << "FAIL: test_tcp_loopback_connection\n";
        all_passed = false;
    }

    return all_passed ? 0 : 1;
}
