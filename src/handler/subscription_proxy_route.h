#ifndef SUBSCRIPTION_PROXY_ROUTE_H_INCLUDED
#define SUBSCRIPTION_PROXY_ROUTE_H_INCLUDED

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include "utils/ip_literal.h"

struct SubscriptionProxyRoute
{
    std::string host;
    std::string proxy;
};

// A forced route must describe an actual curl proxy, never a URL rewrite.
// Invalid descriptors fail closed before a cache hit or network attempt.
inline bool normalizeForcedSubscriptionProxy(const std::string &proxy, std::string &normalized)
{
    normalized.clear();
    if(proxy.empty() || std::any_of(proxy.begin(), proxy.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; })) return false;
    const auto separator = proxy.find("://");
    const bool bare = separator == std::string::npos;
    auto scheme = bare ? std::string("http") : proxy.substr(0, separator);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char c) { return std::tolower(c); });
    if(scheme != "http" && scheme != "https" && scheme != "socks4" && scheme != "socks4a" && scheme != "socks5" && scheme != "socks5h") return false;
    auto authority = bare ? proxy : proxy.substr(separator + 3);
    const auto path = authority.find_first_of("/?#");
    if(path != std::string::npos && (bare || authority.substr(path) != "/")) return false;
    authority.erase(path == std::string::npos ? authority.size() : path);
    auto endpoint = authority;
    const auto user = endpoint.find('@');
    if(user != std::string::npos)
    {
        if(user == 0 || endpoint.find('@', user + 1) != std::string::npos) return false;
        endpoint.erase(0, user + 1);
    }
    if(endpoint.empty()) return false;
    std::string host, port;
    if(endpoint.front() == '[')
    {
        const auto bracket = endpoint.find(']');
        if(bracket == std::string::npos || !isIPv6Literal(endpoint.substr(1, bracket - 1))) return false;
        if(bracket + 1 < endpoint.size())
        {
            if(endpoint[bracket + 1] != ':') return false;
            port = endpoint.substr(bracket + 2);
            if(port.empty()) return false;
        }
    }
    else
    {
        const auto colon = endpoint.find(':');
        host = endpoint.substr(0, colon);
        if(host.empty() || std::any_of(host.begin(), host.end(), [](unsigned char c) { return !(std::isalnum(c) || c == '.' || c == '-' || c == '_'); })) return false;
        if(colon != std::string::npos)
        {
            port = endpoint.substr(colon + 1);
            if(port.empty()) return false;
        }
    }
    // Restore the established host:port syntax without treating NONE/SYSTEM or
    // cors: pseudo-proxies as arbitrary default-HTTP hostnames.
    if(bare && port.empty()) return false;
    if(!port.empty())
    {
        unsigned int value = 0;
        for(unsigned char c : port)
        {
            if(c < '0' || c > '9') return false;
            value = value * 10 + c - '0';
            if(value > 65535) return false;
        }
        if(value == 0) return false;
    }
    normalized = scheme + "://" + authority;
    return true;
}
inline bool isSupportedForcedSubscriptionProxy(const std::string &proxy)
{
    std::string normalized;
    return normalizeForcedSubscriptionProxy(proxy, normalized);
}

inline std::string normalizeSubscriptionProxyHost(std::string host)
{
    const auto not_space = [](unsigned char ch){ return !std::isspace(ch); };
    host.erase(host.begin(), std::find_if(host.begin(), host.end(), not_space));
    host.erase(std::find_if(host.rbegin(), host.rend(), not_space).base(), host.end());
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char ch)
    {
        return static_cast<char>(std::tolower(ch));
    });
    while(host.size() > 1 && host.back() == '.')
        host.pop_back();
    return host;
}

inline std::string subscriptionProxyRouteHostFromUrl(const std::string &url)
{
    const auto scheme_end = url.find("://");
    if(scheme_end == std::string::npos)
        return "";

    std::string scheme = url.substr(0, scheme_end);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char ch)
    {
        return static_cast<char>(std::tolower(ch));
    });
    if(scheme != "http" && scheme != "https")
        return "";

    const auto authority_start = scheme_end + 3;
    const auto authority_end = url.find_first_of("/?#", authority_start);
    std::string authority = url.substr(
        authority_start,
        authority_end == std::string::npos ? std::string::npos : authority_end - authority_start
    );
    const auto userinfo_end = authority.rfind('@');
    if(userinfo_end != std::string::npos)
        authority.erase(0, userinfo_end + 1);
    if(authority.empty())
        return "";

    std::string host;
    if(authority.front() == '[')
    {
        const auto bracket = authority.find(']');
        if(bracket == std::string::npos)
            return "";
        host = authority.substr(1, bracket - 1);
    }
    else
    {
        const auto colon = authority.rfind(':');
        if(colon != std::string::npos && authority.find(':') == colon)
            host = authority.substr(0, colon);
        else
            host = authority;
    }
    return normalizeSubscriptionProxyHost(host);
}

inline const SubscriptionProxyRoute *matchSubscriptionProxyRoute(
    const std::string &url,
    const std::vector<SubscriptionProxyRoute> &routes)
{
    const std::string host = subscriptionProxyRouteHostFromUrl(url);
    if(host.empty())
        return nullptr;

    for(const auto &route : routes)
    {
        if(normalizeSubscriptionProxyHost(route.host) == host)
            return &route;
    }
    return nullptr;
}

#endif // SUBSCRIPTION_PROXY_ROUTE_H_INCLUDED
