#include "packetsail/socket_handle.hpp"

#include <unistd.h>

namespace packetsail {

SocketHandle::SocketHandle(int fd) : fd_(fd) {}

SocketHandle::SocketHandle(SocketHandle&& other) noexcept : fd_(other.fd_) {
    // Invalidate the source to prevent both objects from closing the descriptor.
    other.fd_ = -1;
}

SocketHandle& SocketHandle::operator=(SocketHandle&& other) noexcept {
    if (this != &other) {
        // Release the currently owned socket before taking ownership of another.
        if (fd_ != -1) {
            ::close(fd_);
        }

        fd_ = other.fd_;
        other.fd_ = -1;
    }

    return *this;
}

SocketHandle::~SocketHandle() {
    if (fd_ != -1) {
        ::close(fd_);
    }
}

int SocketHandle::get() const {
    return fd_;
}

}
