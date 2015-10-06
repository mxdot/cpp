#ifndef __UTIL_HPP__
#define __UTIL_HPP__

#include <netdb.h>
#include <cstring>
#include <deque>
#include <random>
#include <string>



namespace util {


std::string get_ip_str(const uint32_t);

//----------------------------------------------------------------------

std::deque<uint32_t> get_ipv4_address(const std::string&);

//----------------------------------------------------------------------

int32_t rnd(int32_t, int32_t);

//----------------------------------------------------------------------

bool set_socket_nonblocking_mode(const uint32_t);

//----------------------------------------------------------------------

std::ostream& tcout();

//----------------------------------------------------------------------

std::string to_lower(std::string);


} // namespace util


#endif // __UTIL_HPP__
