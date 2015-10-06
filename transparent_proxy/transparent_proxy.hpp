#ifndef __TRANSPARENT_PROXY_HPP__
#define __TRANSPARENT_PROXY_HPP__

#include <sys/epoll.h>
#include <array>
#include <deque>
#include <map>
#include <memory>
#include <regex>
#include <vector>



enum class ProxifiedProtocol : uint8_t
{
    HTTP,
    HTTPS,
    UNKNOWN
};

//----------------------------------------------------------------------

struct peer_connection
{
    uint32_t sock_ = 0;
    std::string address_ = "";
    uint16_t port_ = 0;
    bool finalized_ = false; // means FIN send and connection is in half-opened state
    bool established_ = false; // means that connection with peer established
    bool peer_disconnected_ = false; // sets when peer was in established stated and was disconnected
    bool unsent_data_ = false; // means that there is data that failed to send to peer and should be retried
    std::deque<std::deque<uint8_t>> data_for_peer_;
    std::shared_ptr<peer_connection> peer_ = nullptr;
    peer_connection(uint32_t sock): sock_(sock) {};
};

//----------------------------------------------------------------------

class TransparentProxy
{
    public:
        TransparentProxy(std::string, uint16_t);

        bool add_allowed_host(const std::string&);
        bool add_allowed_url(const std::string&);
        void run();
    private:
        void connect_to_remote_upstream(const std::shared_ptr<peer_connection>&, const std::shared_ptr<peer_connection>&, const std::string&, uint16_t);
        ProxifiedProtocol detect_protocol(uint32_t, std::string*, uint16_t*, std::string*);
        void disconnect_cleanly(uint32_t);
        bool epoll_add_socket(uint32_t, int32_t);
        bool epoll_del_socket(uint32_t);
        bool epoll_mod_socket(uint32_t, int32_t);
        void handle_client_connected();
        void handle_connected_to_upstream(uint32_t);
        void handle_data_received(uint32_t);
        void handle_network_event(uint32_t, uint32_t);
        void handle_unsent_data();
        void initialize();
        bool is_connection_allowed(ProxifiedProtocol, std::string, std::string);
        bool is_proto_http(uint32_t, std::string*, uint16_t*, std::string*);
        bool is_proto_https(uint32_t, std::string*, uint16_t*);
        void process_data(uint32_t, uint32_t);
        void process_data_on_established_connection(const std::shared_ptr<peer_connection>&, uint32_t);
        bool process_unsent_data_on_connection(const std::shared_ptr<peer_connection>&, bool*);
        void proxify_tcp_connection(uint32_t, uint32_t, const std::string&, uint16_t);

        std::string address_ = "";
        uint16_t port_ = 0;
        uint32_t listen_sock_ = 0;
        int32_t epollfd_ = 0;
        struct epoll_event ev_;
        static constexpr uint32_t epoll_event_size_ = 1024;
        std::map<uint32_t, std::shared_ptr<peer_connection>> connections_;
        std::array<uint8_t, 10240> io_buffer_;
        bool unsent_data_on_connections_ = false;
        std::vector<std::regex> allowed_hosts_;
        std::vector<std::regex> allowed_urls_;
};


#endif // __TRANSPARENT_PROXY_HPP__
