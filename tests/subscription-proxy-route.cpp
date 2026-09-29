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

    return 0;
}
