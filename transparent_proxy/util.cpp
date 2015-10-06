#include "util.hpp"
#include <arpa/inet.h>
#include <fcntl.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>



namespace util {


std::string get_ip_str(const uint32_t ip)
{
    struct in_addr addr;
    memset(&addr, 0, sizeof(addr));

    addr.s_addr = htonl(ip);

    return inet_ntoa(addr);
}

//----------------------------------------------------------------------

std::deque<uint32_t> get_ipv4_address(const std::string& address)
{
    std::deque<uint32_t> ips;


    struct addrinfo *result;
    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));

    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    try {
        int32_t ret = getaddrinfo(address.c_str(), nullptr, &hint, &result);
        if (ret == 0) {
            struct addrinfo *rp;
            for (rp = result; rp != nullptr; rp = rp->ai_next) {
                uint32_t ip = ((struct sockaddr_in *)rp->ai_addr)->sin_addr.s_addr;

                ips.push_back(htonl(ip));
            }
        }
        freeaddrinfo(result);
    }
    catch (...) {
        freeaddrinfo(result);
        throw;
    }

    return ips;
}

//----------------------------------------------------------------------

int32_t rnd(int32_t from, int32_t to)
{
    std::uniform_int_distribution<int32_t> dist(from, to);

    std::random_device rd;
    std::mt19937 engine(rd());

    return dist(engine);
}

//----------------------------------------------------------------------

bool set_socket_nonblocking_mode(const uint32_t fd)
{
    int32_t flags = 0;
    flags = fcntl(fd, F_GETFD, 0);
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) {
        return false;
    }

    return true;
}

//----------------------------------------------------------------------

std::ostream& tcout()
{
    std::string format_string = "%Y-%m-%d %H:%M:%S";

    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);

    auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count(); // rounding to seconds (to calculate ms)
    auto tp = std::chrono::time_point<std::chrono::system_clock>(std::chrono::seconds(sec));
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - tp).count();

    std::array<char, 64> buffer;
    uint16_t rv = std::strftime(buffer.data(), buffer.size(), format_string.c_str(), std::gmtime(&tt));

    std::stringstream out;
    out << "[" << std::string(buffer.begin(), buffer.begin() + rv) << ":" << std::setfill('0') << std::setw(3) << ms << "]";

    return std::cout << out.str() << "\t";
}

//----------------------------------------------------------------------

std::string to_lower(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);

    return str;
}


} // namespace util
