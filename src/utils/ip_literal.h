#ifndef IP_LITERAL_H_INCLUDED
#define IP_LITERAL_H_INCLUDED
#include <string>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

// Numeric address validation only: scoped/zone-qualified URI hosts are not
// modeled by this converter and remain explicitly unsupported.
inline bool isIPv6Literal(const std::string &address)
{
    in6_addr parsed{};
    return !address.empty() && address.find('%') == std::string::npos &&
           inet_pton(AF_INET6, address.c_str(), &parsed) == 1;
}
#endif
