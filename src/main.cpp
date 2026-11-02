#include "packetsail/socket_handle.hpp"
#include "packetsail/tcp_connection.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cerrno>
#include <iostream>
#include <system_error>

int main() {
    packetsail::SocketHandle server(::socket(AF_INET, SOCK_STREAM, 0));

    if (server.get() == -1) {
        std::cerr << "Failed to create server socket\n";
        return 1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(9090);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::bind(server.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == -1) {
        std::cerr << "Failed to bind server socket\n";
        return 1;
    }

    if (::listen(server.get(), SOMAXCONN) == -1) {
        std::cerr << "Failed to listen on server socket\n";
        return 1;
    }

    std::cout << "PacketSail listening on 127.0.0.1:9090\n";

    while (true) {
        packetsail::SocketHandle client(::accept(server.get(), nullptr, nullptr));

        if (client.get() == -1) {
            if (errno == EINTR) {
                continue;
            }

            const std::error_code error(errno, std::generic_category());
            std::cerr << "Failed to accept connection: " << error.message() << '\n';
            return 1;
        }

        // Prevent writes to disconnected clients from terminating the process.
        const int no_sigpipe = 1;

        if (::setsockopt(client.get(), SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) == -1) {
            const std::error_code error(errno, std::generic_category());
            std::cerr << "Failed to configure client socket: " << error.message() << '\n';
            return 1;
        }

        std::cout << "Client connected\n";

        packetsail::handle_client(client.get());
    }
}
