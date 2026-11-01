#pragma once

namespace packetsail {

class SocketHandle {
public:
    explicit SocketHandle(int fd);
    ~SocketHandle();

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle (SocketHandle&& other) noexcept;
    SocketHandle& operator=(SocketHandle&& other) noexcept;

    int get() const;

private:
    int fd_;
};

}
