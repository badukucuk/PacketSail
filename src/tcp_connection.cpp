#include "packetsail/tcp_connection.hpp"

#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <iostream>
#include <system_error>

namespace packetsail {

ssize_t receive_data(int fd, void* buffer, std::size_t size) {
    ssize_t received = -1;

    // An interrupted receive operation does not necessarily indicate a broken connection.
    do {
        received = ::recv(fd, buffer, size, 0);
    } while (received == -1 && errno == EINTR);

    return received;
}

bool send_all(int fd, const void* buffer, std::size_t size) {
    const auto* data = static_cast<const char*>(buffer);
    std::size_t total_sent = 0;

    // A successful send call may transfer fewer bytes than requested.
    while (total_sent < size) {
        ssize_t sent = -1;

        do {
            sent = ::send(
                fd,
                data + total_sent,
                size - total_sent,
                0
            );
        } while (sent == -1 && errno == EINTR);

        if (sent == -1) {
            return false;
        }

        if (sent == 0) {
            // Treat a zero-byte send as a failure to make forward progress.
            errno = EIO;
            return false;
        }

        total_sent += static_cast<std::size_t>(sent);
    }

    return true;
}

void handle_client(int client_fd) {
    std::array<char, 4096> buffer{};

    while (true) {
        const ssize_t received = receive_data(
            client_fd,
            buffer.data(),
            buffer.size()
        );

        if (received == -1) {
            const std::error_code error(errno, std::generic_category());
            std::cerr << "Client receive error: " << error.message() << '\n';
            return;
        }

        if (received == 0) {
            std::cout << "Client disconnected\n";
            return;
        }

        if (!send_all(
                client_fd,
                buffer.data(),
                static_cast<std::size_t>(received)
            )) {
            const std::error_code error(errno, std::generic_category());
            std::cerr << "Client send error: " << error.message() << '\n';
            return;
        }

        std::cout << "Echoed " << received << " bytes\n";
    }
}

}
