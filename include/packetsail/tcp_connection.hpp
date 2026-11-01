#pragma once

#include <cstddef>
#include <sys/types.h>

namespace packetsail {

ssize_t receive_data(int fd, void* buffer, std::size_t size);

bool send_all(int fd, const void* buffer, std::size_t size);

void handle_client(int client_fd);

}
