#include "packetsail/socket_handle.hpp"

#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <sys/socket.h>
#include <utility>

bool test_socket_closed_on_destruction() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1) {
        return false;
    }

    {
        packetsail::SocketHandle socket(fd);

        if (socket.get() != fd) {
            return false;
        }
    }

    errno = 0;

    return ::fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

bool test_move_constructor() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1) {
        return false;
    }

    {
        packetsail::SocketHandle first(fd);

        {
            packetsail::SocketHandle second(std::move(first));

            if (first.get() != -1 || second.get() != fd) {
                return false;
            }
        }

        errno = 0;

        if (::fcntl(fd, F_GETFD) != -1 || errno != EBADF) {
            return false;
        }
    }

    return true;
}

bool test_move_assignment() {
    const int first_fd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (first_fd == -1) {
        return false;
    }

    packetsail::SocketHandle first(first_fd);

    const int second_fd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (second_fd == -1) {
        return false;
    }

    {
        packetsail::SocketHandle second(second_fd);

        second = std::move(first);

        if (first.get() != -1 || second.get() != first_fd) {
            return false;
        }

        errno = 0;

        if (::fcntl(second_fd, F_GETFD) != -1 || errno != EBADF) {
            return false;
        }

        if (::fcntl(first_fd, F_GETFD) == -1) {
            return false;
        }
    }

    errno = 0;

    return ::fcntl(first_fd, F_GETFD) == -1 && errno == EBADF;
}

bool test_self_move_assignment() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1) {
        return false;
    }

    packetsail::SocketHandle socket(fd);

    socket = std::move(socket);

    if (socket.get() != fd) {
        return false;
    }

    return ::fcntl(fd, F_GETFD) != -1;
}

bool test_invalid_socket_handle() {
    packetsail::SocketHandle socket(-1);

    return socket.get() == -1;
}

int main() {
    bool all_passed = true;

    if (test_socket_closed_on_destruction()) {
        std::cout << "PASS: test_socket_closed_on_destruction\n";
    } else {
        std::cerr << "FAIL: test_socket_closed_on_destruction\n";
        all_passed = false;
    }

    if (test_move_constructor()) {
        std::cout << "PASS: test_move_constructor\n";
    } else {
        std::cerr << "FAIL: test_move_constructor\n";
        all_passed = false;
    }

    if (test_move_assignment()) {
        std::cout << "PASS: test_move_assignment\n";
    } else {
        std::cerr << "FAIL: test_move_assignment\n";
        all_passed = false;
    }

    if (test_self_move_assignment()) {
        std::cout << "PASS: test_self_move_assignment\n";
    } else {
        std::cerr << "FAIL: test_self_move_assignment\n";
        all_passed = false;
    }

    if (test_invalid_socket_handle()) {
        std::cout << "PASS: test_invalid_socket_handle\n";
    } else {
        std::cerr << "FAIL: test_invalid_socket_handle\n";
        all_passed = false;
    }

    return all_passed ? 0 : 1;
}
