#pragma once

namespace packetsail {

// Owns a POSIX socket descriptor and releases it on destruction.
// Ownership is exclusive and can be transferred through move operations.
class SocketHandle {
public:
    explicit SocketHandle(int fd);
    ~SocketHandle();

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept;
    SocketHandle& operator=(SocketHandle&& other) noexcept;

    // Returns the descriptor without transferring ownership.
    int get() const;

private:
    int fd_;
};

}
