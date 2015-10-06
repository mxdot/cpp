#include "transparent_proxy.hpp"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include "util.hpp"


using util::get_ip_str;
using util::get_ipv4_address;
using util::rnd;
using util::set_socket_nonblocking_mode;
using util::tcout;
using util::to_lower;



TransparentProxy::TransparentProxy(std::string address, uint16_t port):
    address_(std::move(address)), port_(port)
{
}

//----------------------------------------------------------------------

bool TransparentProxy::add_allowed_host(const std::string& host)
{
    try {
        std::regex re(host, std::regex::optimize);
        allowed_hosts_.push_back(re);
    }
    catch (...) {
        return false;
    }

    return true;
}

//----------------------------------------------------------------------

bool TransparentProxy::add_allowed_url(const std::string& url)
{
    try {
        std::regex re(url, std::regex::optimize);
        allowed_urls_.push_back(re);
    }
    catch (...) {
        return false;
    }

    return true;
}

//----------------------------------------------------------------------

void TransparentProxy::connect_to_remote_upstream(const std::shared_ptr<peer_connection>& client_conn,
    const std::shared_ptr<peer_connection>& upstream_conn,
    const std::string& address, uint16_t port)
{
    auto ips = get_ipv4_address(address);
    if (ips.size()) {
        tcout() << "addresses: ";
        for (const auto ip: ips) {
            std::cout << get_ip_str(ip) << " ";
        }
        std::cout << std::endl;

        uint32_t ip = ips.at(rnd(0, ips.size() - 1)); // randomly select ip

        struct sockaddr_in remote;
        constexpr uint32_t socklen = sizeof(remote);

        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        remote.sin_addr.s_addr = htonl(ip);

        int32_t enable = 1;
        setsockopt(upstream_conn->sock_, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
        set_socket_nonblocking_mode(upstream_conn->sock_);

        epoll_add_socket(upstream_conn->sock_, EPOLLOUT);

        int32_t rv = connect(upstream_conn->sock_, (const struct sockaddr *)&remote, socklen);
        if (rv < 0) {
            if (errno == EINPROGRESS) {
                return;
            }
        }
        else {
            handle_connected_to_upstream(upstream_conn->sock_);
            return;
        }
    }

    disconnect_cleanly(client_conn->sock_);
    disconnect_cleanly(upstream_conn->sock_);
}

//----------------------------------------------------------------------

ProxifiedProtocol TransparentProxy::detect_protocol(uint32_t bytes, std::string* host, uint16_t* port, std::string* url)
{
    if (is_proto_http(bytes, host, port, url)) {
        return ProxifiedProtocol::HTTP;
    }
    else if (is_proto_https(bytes, host, port)) {
        return ProxifiedProtocol::HTTPS;
    }

    return ProxifiedProtocol::UNKNOWN;
}

//----------------------------------------------------------------------

void TransparentProxy::disconnect_cleanly(uint32_t sock)
{
    if (connections_.count(sock)) {
        auto conn = connections_.at(sock);
        if (conn->peer_) {
            if (!conn->peer_->finalized_) {
                shutdown(conn->peer_->sock_, SHUT_WR);
                conn->peer_->finalized_ = true;
            }

            conn->peer_->peer_disconnected_ = true;
            conn->peer_->peer_ = nullptr;
            conn->peer_ = nullptr;
        }

        connections_.erase(sock);
    }

    shutdown(sock, SHUT_RDWR);
    epoll_del_socket(sock);
    close(sock);
}

//----------------------------------------------------------------------

bool TransparentProxy::epoll_add_socket(uint32_t sock, int32_t ev)
{
    ev_.data.fd = sock;
    ev_.events = ev;
    if (epoll_ctl(epollfd_, EPOLL_CTL_ADD, sock, &ev_) == 0) {
        return true;
    }

    return false;
}

//----------------------------------------------------------------------

bool TransparentProxy::epoll_del_socket(uint32_t sock)
{
    if (epoll_ctl(epollfd_, EPOLL_CTL_DEL, sock, &ev_) == 0) {
        return true;
    }

    return false;
}

//----------------------------------------------------------------------

bool TransparentProxy::epoll_mod_socket(uint32_t sock, int32_t ev)
{
    ev_.data.fd = sock;
    ev_.events = ev;
    if (epoll_ctl(epollfd_, EPOLL_CTL_MOD, sock, &ev_) == 0) {
        return true;
    }

    return false;
}

//----------------------------------------------------------------------

void TransparentProxy::handle_client_connected()
{
    struct sockaddr_in client_addr;
    uint32_t socklen = sizeof(struct sockaddr_in);

    int32_t sock = accept(listen_sock_, (struct sockaddr *)&client_addr, &socklen);
    if (sock > 0) {
        set_socket_nonblocking_mode(sock);

        int32_t ev = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
        if (epoll_add_socket(sock, ev)) {
            connections_[sock] = std::make_shared<peer_connection>(sock);
        }
        else {
            close(sock);
        }
    }
}

//----------------------------------------------------------------------

void TransparentProxy::handle_connected_to_upstream(uint32_t sock)
{
    if (connections_.count(sock)) {
        bool error_occured = false;

        auto upstream_conn = connections_.at(sock);
        auto client_conn = upstream_conn->peer_;

        if (client_conn) {
            for (const auto& packet: client_conn->data_for_peer_) {
                std::vector<uint8_t> data (packet.cbegin(), packet.cend());

                int32_t rv = send(upstream_conn->sock_, data.data(), data.size(), MSG_NOSIGNAL);
                if (rv != static_cast<int32_t>(data.size())) {
                    client_conn->peer_ = nullptr;
                    upstream_conn->peer_ = nullptr;

                    client_conn->peer_disconnected_ = true;
                    upstream_conn->peer_disconnected_ = true;

                    error_occured = true;

                    break;
                }
            }

            if (!error_occured) {
                int32_t ev = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
                if (epoll_mod_socket(upstream_conn->sock_, ev)) {
                    client_conn->data_for_peer_.clear();
                    client_conn->data_for_peer_.shrink_to_fit();

                    client_conn->established_ = true;
                    upstream_conn->established_ = true;

                    return;
                }
            }
        }

        disconnect_cleanly(upstream_conn->sock_);
        if (client_conn) {
            disconnect_cleanly(client_conn->sock_);
        }
    }
}

//----------------------------------------------------------------------

void TransparentProxy::handle_data_received(uint32_t sock)
{
    int32_t bytes = read(sock, io_buffer_.data(), io_buffer_.size());
    if (bytes > 0) {
        process_data(sock, bytes);
    }
    else {
        disconnect_cleanly(sock);
    }
}

//----------------------------------------------------------------------

void TransparentProxy::handle_network_event(uint32_t sock, uint32_t ev)
{
    if ((ev & EPOLLIN) || (ev & EPOLLPRI)) {
        if (sock == listen_sock_) {
            handle_client_connected();
        }
        else {
            handle_data_received(sock);
        } 
    }
    else if (ev & EPOLLOUT) {
        handle_connected_to_upstream(sock);
    }
    else if ((ev & EPOLLERR) || (ev & EPOLLHUP) || (ev & EPOLLRDHUP)) {
        disconnect_cleanly(sock);
    }
}

//----------------------------------------------------------------------

void TransparentProxy::handle_unsent_data()
{
    bool in_progress_connections = false;

    for (const auto& c: connections_) {
        if (c.second->unsent_data_) {
            auto conn = c.second;

            if (conn->peer_) {
                bool in_progress = false;
                if (!process_unsent_data_on_connection(conn, &in_progress)) {
                    if (in_progress) {
                        in_progress_connections = true;
                        continue;
                    }

                    return;
                }
            }
            else {
                disconnect_cleanly(conn->sock_);
                return;
            }
        }
    }

    if (!in_progress_connections) {
        unsent_data_on_connections_ = false;
    }
}

//----------------------------------------------------------------------

void TransparentProxy::initialize()
{
    struct sockaddr_in server_addr;
    uint32_t socklen = sizeof(struct sockaddr_in);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_);
    server_addr.sin_addr.s_addr = inet_addr(address_.c_str());

    int32_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        throw std::runtime_error("unable to create TCP socket");
    }

    set_socket_nonblocking_mode(sock);

    int32_t enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    if (bind(sock, (const struct sockaddr *)&server_addr, socklen) < 0) {
        throw std::runtime_error("unable to bind TCP port for listening");
    }

    listen_sock_ = sock;
    listen(listen_sock_, SOMAXCONN);
}

//----------------------------------------------------------------------

bool TransparentProxy::is_connection_allowed(ProxifiedProtocol proto, std::string host, std::string url)
{
    host = to_lower(host);

    // strip www. prefix
    static std::string prefix = "www.";
    static const uint16_t len = prefix.length();

    if (host.length() > len) {
        if (host.substr(0, len) == prefix) {
            host = host.substr(len, host.length());
        }
    }


    static std::smatch sm;

    for (const auto& re: allowed_hosts_) {
        if (std::regex_match(host, sm, re)) {
            tcout() << "allowed connection to '" << host << "' by host pattern" << std::endl;
            return true;
        }
    }


    if (proto == ProxifiedProtocol::HTTP) {
        url = to_lower(url);

        for (const auto& re: allowed_urls_) {
            if (std::regex_match(url, sm, re)) {
                tcout() << "allowed connection to '" << host << "' by allowed URL pattern" << std::endl;
                return true;
            }
        }
    }


    return false;
}

//----------------------------------------------------------------------

bool TransparentProxy::is_proto_http(uint32_t bytes, std::string* host, uint16_t* port, std::string* url)
{
    std::string header (io_buffer_.begin(), io_buffer_.begin() + bytes);

    std::stringstream out {header};
    std::string line = "";

    bool host_detected = false;
    bool url_detected = false;


    static const std::regex re_host ("^Host:\\s+([^:\\s]+)(?::(\\d{1,5}))?\\s*$", std::regex::optimize);
    static const std::regex re_url ("^(?:CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE)\\s+(/\\S*)\\s+HTTP/\\d\\.\\d\\s*$", std::regex::optimize);


    std::smatch sm;

    while (std::getline(out, line)) {
        if (std::regex_match(line, sm, re_url)) {
            *url = sm[1];

            url_detected = true;
            continue;
        }
        if (std::regex_match(line, sm, re_host)) {
            *host = sm[1];
            std::string port_str = sm[2];
            if (port_str.length()) {
                *port = std::stoul(sm[2]);
            }
            else {
                *port = 80;
            }


            host_detected = true;
            continue;
        }

        if (!line.length() || ((line.size() == 1) && (line.at(0) == '\r'))) {
            break;
        }
    }

    if (host_detected && url_detected) {
        return true;
    }

    return false;
}

//----------------------------------------------------------------------

bool TransparentProxy::is_proto_https(uint32_t bytes, std::string* host, uint16_t* port)
{
    if (bytes < 5) { // 5 bytes it is SSL packet header and 2 ** 14 is maximum SSL packet size (16 KB)
        return false;
    }

    if (io_buffer_.at(0) != 0x16) { // 0x16 means handshake
        return false;
    }

    uint16_t version = (io_buffer_.at(1) << 8) | io_buffer_.at(2);
    if ((version != 0x0300) && (version != 0x0301) && (version != 0x0302) && (version != 0x0303)) {
        return false;
    }

    uint16_t length = (io_buffer_.at(3) << 8) | io_buffer_.at(4);
    if ((bytes - 5) != length) {
        return false;
    }

    if (io_buffer_.at(5) != 0x01) { // 0x01 means Client Hello message
        return false;
    }

    // detecting SNI extension
    std::string payload = "";
    try {
        uint16_t pos = 4; // skip first 5 bytes as header
        while (true) {
            pos++;

            if ((io_buffer_.at(pos) != 0x00) || (io_buffer_.at(pos + 1) != 0x00)) {
                continue;
            }

            uint16_t len = (io_buffer_.at(pos + 2) << 8) | io_buffer_.at(pos + 3);

            if (bytes < static_cast<uint32_t>(pos + 4 + len)) {
                continue;
            }

            uint16_t sni_len = (io_buffer_.at(pos + 4) << 8) | io_buffer_.at(pos + 5);

            if (sni_len >= len) {
                continue;
            }

            // skipping pos + 6
            uint16_t payload_len = (io_buffer_.at(pos + 7) << 8) | io_buffer_.at(pos + 8);
            payload = std::string(io_buffer_.begin() + pos + 9, io_buffer_.begin() + pos + 9 + payload_len);

            break;
        }
    }
    catch (...) {
        return false;
    }

    *host = payload;
    *port = 443;

    return true;
}

//----------------------------------------------------------------------

void TransparentProxy::process_data(uint32_t sock, uint32_t bytes)
{
    if (connections_.count(sock)) {
        auto conn = connections_.at(sock);

        if (conn->peer_) {
            if (conn->established_ && !conn->peer_->finalized_ && !conn->peer_->peer_disconnected_) {
                process_data_on_established_connection(conn, bytes);
            }
            else {
                disconnect_cleanly(sock);
            }
        }
        else if (!conn->peer_disconnected_) {
            std::string host = "";
            uint16_t port = 0;
            std::string url = "";

            auto proto = detect_protocol(bytes, &host, &port, &url);
            if (proto != ProxifiedProtocol::UNKNOWN) {
                if (proto == ProxifiedProtocol::HTTP) {
                    tcout() << "HTTP" << std::endl;
                    tcout() << "    host: " << host << std::endl;
                    tcout() << "    port: " << port << std::endl;
                    tcout() << "     url: " << url << std::endl;
                }
                else if (proto == ProxifiedProtocol::HTTPS) {
                    tcout() << "HTTPS" << std::endl;
                    tcout() << "    host: " << host << std::endl;
                    tcout() << "    port: " << port << std::endl;
                }


                if (is_connection_allowed(proto, host, url)) {
                    proxify_tcp_connection(sock, bytes, host, port);
                    return;
                }
                else {
                    tcout () << "connection to '" << host << "' disallowed" << std::endl;
                }
            }

            disconnect_cleanly(sock);
        }
    }
}

//----------------------------------------------------------------------

void TransparentProxy::process_data_on_established_connection(const std::shared_ptr<peer_connection>& conn, uint32_t bytes)
{
    if (conn->unsent_data_) {
        bool in_progress = false;
        if (!process_unsent_data_on_connection(conn, &in_progress)) {
            if (in_progress) {
                conn->data_for_peer_.push_back(std::deque<uint8_t>(io_buffer_.begin(), io_buffer_.begin() + bytes));
                conn->unsent_data_ = true;
                unsent_data_on_connections_ = true;               
            }
            else {
                disconnect_cleanly(conn->sock_);
            }

            return;
        }
    }


    auto peerfd = conn->peer_->sock_;

    int32_t rv = send(peerfd, io_buffer_.data(), bytes, MSG_NOSIGNAL);
    if (rv == -1) {
        if ((errno != EAGAIN) && (errno != EINPROGRESS)) {
            disconnect_cleanly(conn->sock_);
        }
        else {
            conn->data_for_peer_.push_back(std::deque<uint8_t>(io_buffer_.begin(), io_buffer_.begin() + bytes));
            conn->unsent_data_ = true;

            unsent_data_on_connections_ = true;
        }
    }
}

//----------------------------------------------------------------------

bool TransparentProxy::process_unsent_data_on_connection(const std::shared_ptr<peer_connection>& conn, bool* in_progress)
{
    while (conn->data_for_peer_.size()) {
        auto& packet = conn->data_for_peer_.front();
        std::vector<uint8_t> data (packet.begin(), packet.end());

        auto peerfd = conn->peer_->sock_;

        int32_t rv = send(peerfd, data.data(), data.size(), MSG_NOSIGNAL);
        if (rv == -1) {
            if ((errno != EAGAIN) && (errno != EINPROGRESS)) {
                disconnect_cleanly(conn->sock_);
                return false;
            }

            *in_progress = true;
            return true;
        }
        else {
            conn->data_for_peer_.pop_front();
        }
    }

    conn->unsent_data_ = false;

    return true;
}

//----------------------------------------------------------------------

void TransparentProxy::proxify_tcp_connection(uint32_t sock, uint32_t bytes, const std::string& address, uint16_t port)
{
    int32_t remote_sock = 0;

    try {
        remote_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_sock > 0) {
            auto upstream_conn = std::make_shared<peer_connection>(remote_sock);
            connections_[remote_sock] = upstream_conn;

            auto client_conn = connections_.at(sock);
            if (client_conn) {
                client_conn->peer_ = upstream_conn;
                upstream_conn->peer_ = client_conn;

                client_conn->data_for_peer_.push_back(std::deque<uint8_t>(io_buffer_.begin(), io_buffer_.begin() + bytes));

                upstream_conn->address_ = address;
                upstream_conn->port_ = port;


                connect_to_remote_upstream(client_conn, upstream_conn, address, port);

                return;
            }
        }
    }
    catch (...) {
    }

    if (remote_sock) {
        close(remote_sock);
    }

    disconnect_cleanly(sock);
}

//----------------------------------------------------------------------

void TransparentProxy::run()
{
    initialize();

    struct epoll_event events[epoll_event_size_];
    int32_t epoll_events_count = 0;

    epollfd_ = epoll_create(epoll_event_size_);
    if (epollfd_ == -1) {
        throw std::runtime_error("Unable to create epoll socket");
    }

    int32_t ev = EPOLLIN | EPOLLPRI | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    if (!epoll_add_socket(listen_sock_, ev)) {
        throw std::runtime_error("Unable to add socket to epoll for Web Proxy");
    }


    while (true) {
        try {
            epoll_events_count = epoll_wait(epollfd_, events, epoll_event_size_, -1);
            for (uint16_t n = 0; n < epoll_events_count; ++n) {
                handle_network_event(events[n].data.fd, events[n].events);
            }

            if (unsent_data_on_connections_) {
                handle_unsent_data();
            }
        }
        catch (...) {
        }
    }
}
