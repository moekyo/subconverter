#ifndef PROXY_H_INCLUDED
#define PROXY_H_INCLUDED

#include <string>
#include <vector>
#include <optional>
#include <map>
#include <memory>

#include "utils/tribool.h"

using String = std::string;
using StringArray = std::vector<String>;
struct ConversionReport;

enum class ProxyType
{
    Unknown,
    Shadowsocks,
    ShadowsocksR,
    VMess,
    Trojan,
    Snell,
    HTTP,
    HTTPS,
    SOCKS5,
    WireGuard,
    Hysteria,
    Hysteria2,
    AnyTLS,
    VLESS,
    TUIC,
};

inline String getProxyTypeName(ProxyType type)
{
    switch(type)
    {
    case ProxyType::Shadowsocks:
        return "SS";
    case ProxyType::ShadowsocksR:
        return "SSR";
    case ProxyType::VMess:
        return "VMess";
    case ProxyType::Trojan:
        return "Trojan";
    case ProxyType::Snell:
        return "Snell";
    case ProxyType::HTTP:
        return "HTTP";
    case ProxyType::HTTPS:
        return "HTTPS";
    case ProxyType::SOCKS5:
        return "SOCKS5";
    case ProxyType::WireGuard:
        return "WireGuard";
    case ProxyType::Hysteria:
        return "Hysteria";
    case ProxyType::Hysteria2:
        return "Hysteria2";
    case ProxyType::AnyTLS:
        return "AnyTLS";
    case ProxyType::VLESS:
        return "VLESS";
    case ProxyType::TUIC:
        return "TUIC";
    default:
        return "Unknown";
    }
}

// Mihomo-specific TUIC options are typed and explicitly allowlisted by the parser.
// An absent option stays absent, so the client keeps its own versioned defaults.
struct TuicOptions
{
    std::map<String, String> Strings;
    std::map<String, uint32_t> Integers;
    std::map<String, bool> Booleans;
};

// Request-local source identity survives parser rejection, filtering and renaming.
// Exporters may read this state but never store target-specific decisions here.
struct SourceNodeIdentity
{
    enum class State { Rejected, Parsed, Filtered };
    std::string Name, Dependency;
    bool ChainDeclared = false;
    State Status = State::Rejected;
};
struct SourceNodeRegistry
{
    std::shared_ptr<ConversionReport> Report;
    std::vector<std::shared_ptr<SourceNodeIdentity>> Records;
    std::shared_ptr<SourceNodeIdentity> reserve(const std::string &name)
    {
        auto record = std::make_shared<SourceNodeIdentity>();
        record->Name = name;
        Records.push_back(record);
        return record;
    }
};
using SourceRegistry = std::shared_ptr<SourceNodeRegistry>;

struct Proxy
{
    ProxyType Type = ProxyType::Unknown;
    uint32_t Id = 0;
    uint32_t GroupId = 0;
    String Group;
    String Remark;
    SourceRegistry SourceRegistryRef;
    std::shared_ptr<SourceNodeIdentity> SourceIdentity;
    String Hostname;
    uint16_t Port = 0;

    String Username;
    String Password;
    String EncryptMethod;
    String Plugin;
    String PluginOption;
    String Protocol;
    String ProtocolParam;
    String OBFS;
    String OBFSParam;
    String UserId;
    uint16_t AlterId = 0;
    String TransferProtocol;
    String FakeType;
    String Flow;
    String ShortId;
    String PacketEncoding;
    String CertificateFingerprint;
    tribool RealitySupportX25519MLKEM768;
    bool TLSSecure = false;

    String Host;
    String Path;
    String Edge;

    String QUICSecure;
    String QUICSecret;

    tribool UDP;
    tribool TCPFastOpen;
    tribool AllowInsecure;
    tribool TLS13;

    String UnderlyingProxy;

    uint16_t SnellVersion = 0;
    String ServerName;

    String SelfIP;
    String SelfIPv6;
    String PublicKey;
    String PrivateKey;
    String PreSharedKey;
    StringArray DnsServers;
    uint16_t Mtu = 0;
    String AllowedIPs = "0.0.0.0/0, ::/0";
    uint16_t KeepAlive = 0;
    String TestUrl;
    String ClientId;

    String Ports;
    String Up;
    uint32_t UpSpeed = 0;
    String Down;
    uint32_t DownSpeed = 0;
    String AuthStr;
    String SNI;
    String Fingerprint;
    // Keep certificate pinning distinct from the TLS ClientHello fingerprint.
    String ClientFingerprint;
    std::optional<uint32_t> IdleSessionCheckInterval;
    std::optional<uint32_t> IdleSessionTimeout;
    std::optional<uint32_t> MinIdleSession;
    String Ca;
    String CaStr;
    uint32_t RecvWindowConn = 0;
    uint32_t RecvWindow = 0;
    tribool DisableMtuDiscovery;
    uint32_t HopInterval = 0;
    StringArray Alpn;
    bool AlpnSpecified = false;
    TuicOptions Tuic;

    uint32_t CWND = 0;
};

inline void attachSourceIdentity(Proxy &node, const SourceRegistry &registry,
                                 std::shared_ptr<SourceNodeIdentity> record = {})
{
    if(node.SourceIdentity)
    {
        if(node.SourceIdentity->Status != SourceNodeIdentity::State::Rejected) return;
        record = node.SourceIdentity;
    }
    if(!record) record = registry->reserve(node.Remark);
    record->Name = node.Remark; // Includes a parser-derived default or QX tag.
    record->Status = SourceNodeIdentity::State::Parsed;
    record->Dependency = node.UnderlyingProxy;
    record->ChainDeclared = record->ChainDeclared || !node.UnderlyingProxy.empty();
    node.SourceRegistryRef = registry;
    node.SourceIdentity = std::move(record);
}
inline void reserveSourceIdentity(Proxy &node, const SourceRegistry &registry, const std::string &name)
{
    if(!registry || node.SourceIdentity) return;
    node.SourceRegistryRef = registry;
    node.SourceIdentity = registry->reserve(name);
}
inline void markSourceFiltered(const Proxy &node)
{
    if(node.SourceIdentity) node.SourceIdentity->Status = SourceNodeIdentity::State::Filtered;
}

#define SS_DEFAULT_GROUP "SSProvider"
#define SSR_DEFAULT_GROUP "SSRProvider"
#define V2RAY_DEFAULT_GROUP "V2RayProvider"
#define SOCKS_DEFAULT_GROUP "SocksProvider"
#define HTTP_DEFAULT_GROUP "HTTPProvider"
#define TROJAN_DEFAULT_GROUP "TrojanProvider"
#define SNELL_DEFAULT_GROUP "SnellProvider"
#define WG_DEFAULT_GROUP "WireGuardProvider"
#define HYSTERIA_DEFAULT_GROUP "HysteriaProvider"
#define HYSTERIA2_DEFAULT_GROUP "Hysteria2Provider"
#define ANYTLS_DEFAULT_GROUP "AnyTLSProvider"
#define TUIC_DEFAULT_GROUP "TUICProvider"

#endif // PROXY_H_INCLUDED
