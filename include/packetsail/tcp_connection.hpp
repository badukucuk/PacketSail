#pragma once

#include <cstddef>
#include <sys/types.h>

namespace packetsail {

// Receives up to size bytes, retrying interrupted system calls.
// Returns the byte count, zero on orderly shutdown, or -1 on error.
ssize_t receive_data(int fd, void* buffer, std::size_t size);

// Sends all requested bytes, retrying interrupted system calls.
// Returns false on failure and sets errno to indicate the error.
bool send_all(int fd, const void* buffer, std::size_t size);

// Handles a connected client without taking ownership of its descriptor.
void handle_client(int client_fd);

}
