#ifndef SHARE_URI_H_INCLUDED
#define SHARE_URI_H_INCLUDED

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <string>

#include "utils/network.h"
#include "utils/tribool.h"

// Strict, local-only URI parsing. Never log a URI, password or query value.
namespace share_uri
{
inline int hex(unsigned char c)
{
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool decode(const std::string &input, std::string &out)
{
    out.clear();
    for(size_t i = 0; i < input.size(); ++i)
    {
        unsigned char c = input[i];
        if(c == '%')
        {
            if(i + 2 >= input.size() || hex(input[i + 1]) < 0 || hex(input[i + 2]) < 0)
                return false;
            c = static_cast<unsigned char>(hex(input[i + 1]) * 16 + hex(input[i + 2]));
            i += 2;
        }
        if(c < 0x20 || c == 0x7f) return false;
        out += static_cast<char>(c); // '+' is a literal URI character, not form data.
    }
    return true;
}

inline bool number(const std::string &text, uint32_t &value, uint32_t limit = UINT32_MAX)
{
    if(text.empty()) return false;
    uint64_t n = 0;
    for(unsigned char c : text)
    {
        if(c < '0' || c > '9') return false;
        n = n * 10 + c - '0';
        if(n > limit) return false;
    }
    value = static_cast<uint32_t>(n);
    return true;
}

inline bool portRanges(const std::string &text, uint32_t &first)
{
    if(text.empty()) return false;
    bool initial = true;
    size_t start = 0;
    while(start < text.size())
    {
        auto end = text.find(',', start);
        if(end == std::string::npos) end = text.size();
        const auto part = text.substr(start, end - start);
        const auto dash = part.find('-');
        uint32_t low = 0, high = 0;
        if(!number(part.substr(0, dash), low, 65535) || low == 0) return false;
        if(dash != std::string::npos && (!number(part.substr(dash + 1), high, 65535) || high < low)) return false;
        if(initial) { first = low; initial = false; }
        if(end == text.size()) return true;
        start = end + 1;
    }
    return false; // trailing comma
}

struct Link
{
    std::string userinfo, raw_userinfo, server, port, ports, remark;
    std::map<std::string, std::string> query;

    std::string get(const std::string &key) const
    {
        auto p = query.find(key);
        return p == query.end() ? "" : p->second;
    }

    bool boolean(const std::string &key, tribool &value) const
    {
        auto p = query.find(key);
        if(p == query.end()) return true;
        if(p->second != "true" && p->second != "false" && p->second != "1" && p->second != "0")
            return false;
        value = p->second;
        return true;
    }
};

inline bool parse(const std::string &input, const std::string &scheme, Link &out, const std::string &default_port = "", bool allow_port_ranges = false, bool allow_empty_auth = false)
{
    const std::string prefix = scheme + "://";
    if(input.compare(0, prefix.size(), prefix) != 0) return false;
    if(std::any_of(input.begin(), input.end(), [](unsigned char c) { return c <= 0x20 || c == 0x7f; }))
        return false;
    std::string authority = input.substr(prefix.size());
    auto p = authority.find('#');
    if(p != std::string::npos)
    {
        if(!decode(authority.substr(p + 1), out.remark)) return false;
        authority.erase(p);
    }
    p = authority.find('?');
    if(p != std::string::npos)
    {
        const std::string query = authority.substr(p + 1);
        authority.erase(p);
        for(size_t start = 0; start < query.size();)
        {
            auto end = query.find('&', start);
            if(end == std::string::npos) end = query.size();
            const auto pair = query.substr(start, end - start);
            const auto equal = pair.find('=');
            if(equal == std::string::npos) return false;
            std::string key, value;
            if(!decode(pair.substr(0, equal), key) || !decode(pair.substr(equal + 1), value) || key.empty()) return false;
            if(!out.query.emplace(key, value).second) return false;
            start = end + 1;
        }
    }
    if(!authority.empty() && authority.back() == '/') authority.pop_back();
    p = authority.find('@');
    if(p == std::string::npos)
    {
        if(!allow_empty_auth) return false;
    }
    else
    {
        if(authority.find('@', p + 1) != std::string::npos) return false;
        out.raw_userinfo = authority.substr(0, p);
        if(!decode(out.raw_userinfo, out.userinfo) || (out.userinfo.empty() && !allow_empty_auth)) return false;
        authority.erase(0, p + 1);
    }
    if(authority.empty()) return false;
    if(authority[0] == '[')
    {
        p = authority.find(']');
        if(p == std::string::npos) return false;
        if(p + 1 < authority.size() && authority[p + 1] != ':') return false;
        out.server = authority.substr(1, p - 1);
        if(!isIPv6(out.server)) return false;
        out.port = p + 1 == authority.size() ? default_port : authority.substr(p + 2);
    }
    else
    {
        p = authority.find(':');
        out.server = authority.substr(0, p);
        out.port = p == std::string::npos ? default_port : authority.substr(p + 1);
        if(out.server.empty() || std::any_of(out.server.begin(), out.server.end(), [](unsigned char c) {
            return !(std::isalnum(c) || c == '.' || c == '-' || c == '_');
        })) return false;
    }
    uint32_t port = 0;
    if(allow_port_ranges && out.port.find_first_of(",-") != std::string::npos)
    {
        if(!portRanges(out.port, port)) return false;
        out.ports = out.port;
        out.port = std::to_string(port);
    }
    else if(!number(out.port, port, 65535) || port == 0) return false;
    if(out.remark.empty()) out.remark = out.server + ":" + out.port;
    return true;
}
}

#endif
