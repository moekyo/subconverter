#include <cassert>
#include <string>
#include <vector>

#include "handler/subscription_proxy_route.h"

int main()
{
    assert(subscriptionProxyRouteHostFromUrl(
        "HTTPS://user:pass@VPS-Proxy.Example.COM.:443/path?q=1#fragment")
        == "vps-proxy.example.com");
    assert(subscriptionProxyRouteHostFromUrl("http://192.0.2.1:8080/sub") == "192.0.2.1");
    assert(subscriptionProxyRouteHostFromUrl("data:text/plain,hello").empty());
    assert(subscriptionProxyRouteHostFromUrl("https:///missing-host").empty());

    std::vector<SubscriptionProxyRoute> routes {
        {"VPS-Proxy.Example.COM.", "http://router.local:7890"},
        {"other.example.com", "socks5://router.local:7893"},
    };
    const auto *first = matchSubscriptionProxyRoute(
        "https://vps-proxy.example.com/token",
        routes);
    assert(first != nullptr);
    assert(first->proxy == "http://router.local:7890");

    assert(matchSubscriptionProxyRoute(
        "https://sub.vps-proxy.example.com/token",
        routes) == nullptr);
    assert(matchSubscriptionProxyRoute(
        "https://other.example.com/token",
        routes)->proxy == "socks5://router.local:7893");
    assert(matchSubscriptionProxyRoute(
        "https://unmatched.example.com/token",
        routes) == nullptr);

    for(const auto &proxy : {"http://127.0.0.1:7890", "HTTPS://proxy.example", "socks5h://user:pass@[::1]:1080", "socks4a://proxy.example/"})
        assert(isSupportedForcedSubscriptionProxy(proxy));
    for(const auto &proxy : {"", "NONE", "cors:", "cors:https://proxy.example/", "file:///tmp/proxy", "http://", "http://:8080", "http://proxy.example:0", "http://proxy.example:65536", "http://proxy.example:443junk", "http://proxy.example/path"})
        assert(!isSupportedForcedSubscriptionProxy(proxy));

    std::string normalized;
    assert(normalizeForcedSubscriptionProxy("127.0.0.1:7890", normalized) && normalized == "http://127.0.0.1:7890");
    assert(normalizeForcedSubscriptionProxy("[::ffff:192.0.2.1]:7890", normalized));
    for(const auto &proxy : {"SYSTEM", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:bad", "127.0.0.1:7890/path", "http://[1:2:3:4:5:6:7:8:9::]:443", "http://bad,host:443", "http://[fe80::1%25eth0]:443"})
        assert(!isSupportedForcedSubscriptionProxy(proxy));
    return 0;
}
