#include <string>
#include <map>
#include <set>

#include "utils/base64/base64.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/network.h"
#include "utils/rapidjson_extra.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "config/proxy.h"
#include "subparser.h"
#include "share_uri.h"
#include "utils/logger.h"

using namespace rapidjson;
using namespace rapidjson_ext;
using namespace YAML;

string_array ss_ciphers = {"rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305", "2022-blake3-chacha8-poly1305"};
string_array ssr_ciphers = {"none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"};

std::map<std::string, std::string> parsedMD5;
std::string modSSMD5 = "f7653207090ce3389115e9c88541afe0";

//remake from speedtestutil

void commonConstruct(Proxy &node, ProxyType type, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const tribool &udp, const tribool &tfo, const tribool &scv, const tribool &tls13,  const std::string& underlying_proxy)
{
    node.Type = type;
    node.Group = group;
    node.Remark = remarks;
    node.Hostname = server;
    node.UnderlyingProxy = underlying_proxy;
    node.Port = to_int(port);
    node.UDP = udp;
    node.TCPFastOpen = tfo;
    node.AllowInsecure = scv;
    node.TLS13 = tls13;
}

void vmessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &type, const std::string &id, const std::string &aid, const std::string &net, const std::string &cipher, const std::string &path, const std::string &host, const std::string &edge, const std::string &tls, const std::string &sni, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::VMess, group, remarks, add, port, udp, tfo, scv, tls13, underlying_proxy);
    node.UserId = id.empty() ? "00000000-0000-0000-0000-000000000000" : id;
    node.AlterId = to_int(aid);
    node.EncryptMethod = cipher;
    node.TransferProtocol = net.empty() ? "tcp" : net;
    node.Edge = edge;
    node.ServerName = sni;

    if(net == "quic")
    {
        node.QUICSecure = host;
        node.QUICSecret = path;
    }
    else
    {
        node.Host = (host.empty() && !isIPv4(add) && !isIPv6(add)) ? add.data() : trim(host);
        node.Path = path.empty() ? "/" : trim(path);
    }
    node.FakeType = type;
    node.TLSSecure = tls == "tls";
}

void vlessConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &add, const std::string &port, const std::string &id, const std::string &flow, const std::string &net, const std::string &path, const std::string &host, bool tlssecure, const std::string &sni, const std::string &fingerprint, const std::string &public_key, const std::string &short_id, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::VLESS, group, remarks, add, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.UserId = id;
    node.EncryptMethod = "none";
    node.TransferProtocol = net.empty() ? "tcp" : net;
    node.Path = path;
    node.Host = host;
    node.Flow = flow;
    node.ShortId = short_id;
    node.ServerName = sni;
    node.Fingerprint = fingerprint;
    node.PublicKey = public_key;
    node.TLSSecure = tlssecure;
}

void ssrConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &protocol, const std::string &method, const std::string &obfs, const std::string &password, const std::string &obfsparam, const std::string &protoparam, tribool udp, tribool tfo, tribool scv,const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::ShadowsocksR, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Protocol = protocol;
    node.ProtocolParam = protoparam;
    node.OBFS = obfs;
    node.OBFSParam = obfsparam;
}

void ssConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &method, const std::string &plugin, const std::string &pluginopts, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::Shadowsocks, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.EncryptMethod = method;
    node.Plugin = plugin;
    node.PluginOption = pluginopts;
}

void socksConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::SOCKS5, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Username = username;
    node.Password = password;
}

void httpConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &username, const std::string &password, bool tls, tribool tfo, tribool scv, tribool tls13,const std::string& underlying_proxy)
{
    commonConstruct(node, tls ? ProxyType::HTTPS : ProxyType::HTTP, group, remarks, server, port, tribool(), tfo, scv, tls13, underlying_proxy);
    node.Username = username;
    node.Password = password;
    node.TLSSecure = tls;
}

void trojanConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &network, const std::string &host, const std::string &path, bool tlssecure, tribool udp, tribool tfo, tribool scv, tribool tls13, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::Trojan, group, remarks, server, port, udp, tfo, scv, tls13, underlying_proxy);
    node.Password = password;
    node.Host = host;
    node.TLSSecure = tlssecure;
    node.TransferProtocol = network.empty() ? "tcp" : network;
    node.Path = path;
}

void snellConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &password, const std::string &obfs, const std::string &host, uint16_t version, tribool udp, tribool tfo, tribool scv, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::Snell, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.Password = password;
    node.OBFS = obfs;
    node.Host = host;
    node.SnellVersion = version;
}

void wireguardConstruct(Proxy &node, const std::string &group, const std::string &remarks, const std::string &server, const std::string &port, const std::string &selfIp, const std::string &selfIpv6, const std::string &privKey, const std::string &pubKey, const std::string &psk, const string_array &dns, const std::string &mtu, const std::string &keepalive, const std::string &testUrl, const std::string &clientId, const tribool &udp, const std::string& underlying_proxy)
{
    commonConstruct(node, ProxyType::WireGuard, group, remarks, server, port, udp, tribool(), tribool(), tribool(), underlying_proxy);
    node.SelfIP = selfIp;
    node.SelfIPv6 = selfIpv6;
    node.PrivateKey = privKey;
    node.PublicKey = pubKey;
    node.PreSharedKey = psk;
    node.DnsServers = dns;
    node.Mtu = to_int(mtu);
    node.KeepAlive = to_int(keepalive);
    node.TestUrl = testUrl;
    node.ClientId = clientId;
}

void hysteriaConstruct(
    Proxy &node,
    const std::string &group,
    const std::string &remarks,
    const std::string &server,
    const std::string &port,
    const std::string &ports,
    const std::string &protocol,
    const std::string &obfs_protocol,
    const std::string &up,
    const std::string &up_speed,
    const std::string &down,
    const std::string &down_speed,
    const std::string &auth,
    const std::string &auth_str,
    const std::string &obfs,
    const std::string &sni,
    const std::string &fingerprint,
    const std::string &ca,
    const std::string &ca_str,
    const std::string &recv_window_conn,
    const std::string &recv_window,
    const std::string &disable_mtu_discovery,
    const std::string &hop_interval,
    const std::string &alpn,
    tribool tfo,
    tribool scv,
    const std::string &underlying_proxy
) {
    commonConstruct(node, ProxyType::Hysteria, group, remarks, server, port, tribool(), tfo, scv, tribool(), underlying_proxy);
    node.Ports = ports;
    node.Protocol = protocol;
    node.OBFSParam = obfs_protocol;
    if (!up.empty())
    {
        if (up.length() > 4 && up.find("bps") == up.length() - 3)
        
            node.Up = up;
        else if (to_int(up))
        {
            node.UpSpeed = to_int(up);
            node.Up = up + " Mbps";
        }
    }
    if (!up_speed.empty())
        node.UpSpeed = to_int(up_speed);
    if (!down.empty())
    {
        if (down.length() > 4 && down.find("bps") == down.length() - 3)
            node.Down = down;
        else if (to_int(down))
        {
            node.DownSpeed = to_int(down);
            node.Down = down + " Mbps";
        }
    }
    if (!down_speed.empty())
        node.DownSpeed = to_int(down_speed);
    node.AuthStr = auth_str;
    if (!auth.empty())
        node.AuthStr = base64Decode(auth);
    node.TLSSecure = true;
    node.OBFS = obfs;
    node.SNI = sni;
    node.Fingerprint = fingerprint;
    node.Ca = ca;
    node.CaStr = ca_str;
    node.RecvWindowConn = to_int(recv_window_conn);
    node.RecvWindow = to_int(recv_window);
    node.DisableMtuDiscovery = disable_mtu_discovery;
    node.HopInterval = to_int(hop_interval);
    if (!alpn.empty())
    {
        node.Alpn = StringArray {alpn};
    }
}

void hysteria2Construct(
    Proxy &node, 
    const std::string &group,
    const std::string &remarks,
    const std::string &server, 
    const std::string &port,
    const std::string &ports,
    const std::string &up, 
    const std::string &down,
    const std::string &password,
    const std::string &obfs,
    const std::string &obfs_password,
    const std::string &sni,
    const std::string &fingerprint,
    const std::string &alpn,
    const std::string &ca,
    const std::string &caStr,
    const std::string &cwnd,
    const std::string &hop_interval, 
    tribool tfo, 
    tribool scv, 
    const std::string &underlying_proxy
) {
    commonConstruct(node, ProxyType::Hysteria2, group, remarks, server, port, tribool(), tfo, scv, tribool(), underlying_proxy);
    node.TLSSecure = true;
    node.UpSpeed = to_int(up);
    node.DownSpeed = to_int(down);
    node.Ports = ports;
    node.Password = password;
    node.OBFS = obfs;
    node.OBFSParam = obfs_password;
    node.SNI = sni;
    node.Fingerprint = fingerprint;
    if (!alpn.empty())
    {
        node.Alpn = StringArray {alpn};
    }
    node.Ca = ca;
    node.CaStr = caStr;
    node.CWND = to_int(cwnd);
    node.HopInterval = to_int(hop_interval);
}

void anyTLSConstruct(
    Proxy &node,
    const std::string &group,
    const std::string &remarks,
    const std::string &server,
    const std::string &port,
    const std::string &password,
    const std::string &sni,
    tribool udp,
    tribool tfo,
    tribool scv,
    const std::string &underlying_proxy
) {
    commonConstruct(node, ProxyType::AnyTLS, group, remarks, server, port, udp, tfo, scv, tribool(), underlying_proxy);
    node.TLSSecure = true;
    node.Password = password;
    node.SNI = sni;
}

void explodeVmess(std::string vmess, Proxy &node, SourceRegistry registry)
{
    std::string version, ps, add, port, type, id, aid, net, path, host, tls, sni;
    Document jsondata;
    std::vector<std::string> vArray;

    if(regMatch(vmess, "vmess://([A-Za-z0-9-_]+)\\?(.*)")) //shadowrocket style link
    {
        explodeShadowrocket(vmess, node);
        return;
    }
    else if(regMatch(vmess, "vmess://(.*?)@(.*)"))
    {
        explodeStdVMess(vmess, node);
        return;
    }
    else if(regMatch(vmess, "vmess1://(.*?)\\?(.*)")) //kitsunebi style link
    {
        explodeKitsunebi(vmess, node);
        return;
    }
    vmess = urlSafeBase64Decode(regReplace(vmess, "(vmess|vmess1)://", ""));
    if(regMatch(vmess, "(.*?) = (.*)"))
    {
        explodeQuan(vmess, node);
        return;
    }
    jsondata.Parse(vmess.data());
    if(jsondata.HasParseError() || !jsondata.IsObject())
        return;

    version = "1"; //link without version will treat as version 1
    GetMember(jsondata, "v", version); //try to get version

    GetMember(jsondata, "ps", ps);
    reserveSourceIdentity(node, registry, ps);
    GetMember(jsondata, "add", add);
    port = GetMember(jsondata, "port");
    if(port == "0")
        return;
    GetMember(jsondata, "type", type);
    GetMember(jsondata, "id", id);
    GetMember(jsondata, "aid", aid);
    GetMember(jsondata, "net", net);
    GetMember(jsondata, "tls", tls);

    GetMember(jsondata, "host", host);
    GetMember(jsondata, "sni", sni);
    switch(to_int(version))
    {
    case 1:
        if(!host.empty())
        {
            vArray = split(host, ";");
            if(vArray.size() == 2)
            {
                host = vArray[0];
                path = vArray[1];
            }
        }
        break;
    case 2:
        path = GetMember(jsondata, "path");
        break;
    }

    add = trim(add);

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, "auto", path, host, "", tls, sni);
}

void explodeVmessConf(std::string content, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    Document json;
    rapidjson::Value nodejson, settings;
    std::string group, ps, add, port, type, id, aid, net, path, host, edge, tls, cipher, subid, sni;
    tribool udp, tfo, scv;
    int configType;
    uint32_t index = nodes.size();
    std::map<std::string, std::string> subdata;
    std::map<std::string, std::string>::iterator iter;
    std::string streamset = "streamSettings", tcpset = "tcpSettings", wsset = "wsSettings";
    regGetMatch(content, "((?i)streamsettings)", 2, 0, &streamset);
    regGetMatch(content, "((?i)tcpsettings)", 2, 0, &tcpset);
    regGetMatch(content, "((?1)wssettings)", 2, 0, &wsset);

    json.Parse(content.data());
    if(json.HasParseError() || !json.IsObject())
        return;
    try
    {
        if(json.HasMember("outbounds")) //single config
        {
            if(json["outbounds"].Size() > 0 && json["outbounds"][0].HasMember("settings") && json["outbounds"][0]["settings"].HasMember("vnext") && json["outbounds"][0]["settings"]["vnext"].Size() > 0)
            {
                Proxy node;
                nodejson = json["outbounds"][0];
                add = GetMember(nodejson["settings"]["vnext"][0], "address");
                port = GetMember(nodejson["settings"]["vnext"][0], "port");
                auto source_record = registry->reserve(add + ":" + port);
                if(port == "0")
                    return;
                if(nodejson["settings"]["vnext"][0]["users"].Size())
                {
                    id = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "id");
                    aid = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "alterId");
                    cipher = GetMember(nodejson["settings"]["vnext"][0]["users"][0], "security");
                }
                if(nodejson.HasMember(streamset.data()))
                {
                    net = GetMember(nodejson[streamset.data()], "network");
                    tls = GetMember(nodejson[streamset.data()], "security");
                    if(net == "ws")
                    {
                        if(nodejson[streamset.data()].HasMember(wsset.data()))
                            settings = nodejson[streamset.data()][wsset.data()];
                        else
                            settings.RemoveAllMembers();
                        path = GetMember(settings, "path");
                        if(settings.HasMember("headers"))
                        {
                            host = GetMember(settings["headers"], "Host");
                            edge = GetMember(settings["headers"], "Edge");
                        }
                    }
                    if(nodejson[streamset.data()].HasMember(tcpset.data()))
                        settings = nodejson[streamset.data()][tcpset.data()];
                    else
                        settings.RemoveAllMembers();
                    if(settings.IsObject() && settings.HasMember("header"))
                    {
                        type = GetMember(settings["header"], "type");
                        if(type == "http")
                        {
                            if(settings["header"].HasMember("request"))
                            {
                                if(settings["header"]["request"].HasMember("path") && settings["header"]["request"]["path"].Size())
                                    settings["header"]["request"]["path"][0] >> path;
                                if(settings["header"]["request"].HasMember("headers"))
                                {
                                    host = GetMember(settings["header"]["request"]["headers"], "Host");
                                    edge = GetMember(settings["header"]["request"]["headers"], "Edge");
                                }
                            }
                        }
                    }
                }
                vmessConstruct(node, V2RAY_DEFAULT_GROUP, add + ":" + port, add, port, type, id, aid, net, cipher, path, host, edge, tls, "", udp, tfo, scv);
                attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
            }
            return;
        }
    }
    catch(std::exception & e)
    {
        //writeLog(0, "VMessConf parser throws an error. Leaving...", LOG_LEVEL_WARNING);
        //return;
        //ignore
        throw;
    }
    //read all subscribe remark as group name
    for(uint32_t i = 0; i < json["subItem"].Size(); i++)
        subdata.insert(std::pair<std::string, std::string>(json["subItem"][i]["id"].GetString(), json["subItem"][i]["remarks"].GetString()));

    for(uint32_t i = 0; i < json["vmess"].Size(); i++)
    {
        Proxy node;
        auto source_record = registry->reserve(GetMember(json["vmess"][i], "remarks"));
        if(json["vmess"][i]["address"].IsNull() || json["vmess"][i]["port"].IsNull() || json["vmess"][i]["id"].IsNull())
            continue;

        //common info
        json["vmess"][i]["remarks"] >> ps;
        json["vmess"][i]["address"] >> add;
        port = GetMember(json["vmess"][i], "port");
        if(port == "0")
            continue;
        json["vmess"][i]["subid"] >> subid;

        if(!subid.empty())
        {
            iter = subdata.find(subid);
            if(iter != subdata.end())
                group = iter->second;
        }
        if(ps.empty())
            ps = add + ":" + port;

        scv = GetMember(json["vmess"][i], "allowInsecure");
        json["vmess"][i]["configType"] >> configType;
        switch(configType)
        {
        case 1: //vmess config
            json["vmess"][i]["headerType"] >> type;
            json["vmess"][i]["id"] >> id;
            json["vmess"][i]["alterId"] >> aid;
            json["vmess"][i]["network"] >> net;
            json["vmess"][i]["path"] >> path;
            json["vmess"][i]["requestHost"] >> host;
            json["vmess"][i]["streamSecurity"] >> tls;
            json["vmess"][i]["security"] >> cipher;
            json["vmess"][i]["sni"] >> sni;
            vmessConstruct(node, V2RAY_DEFAULT_GROUP, ps, add, port, type, id, aid, net, cipher, path, host, "", tls, sni, udp, tfo, scv);
            break;
        case 3: //ss config
            json["vmess"][i]["id"] >> id;
            json["vmess"][i]["security"] >> cipher;
            ssConstruct(node, SS_DEFAULT_GROUP, ps, add, port, id, cipher, "", "", udp, tfo, scv);
            break;
        case 4: //socks config
            socksConstruct(node, SOCKS_DEFAULT_GROUP, ps, add, port, "", "", udp, tfo, scv);
            break;
        default:
            continue;
        }
        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSS(std::string uri, Proxy &node)
{
    // SIP002: AEAD-2022 uses percent-encoded plaintext userinfo. Keep legacy
    // Base64 userinfo and whole-authority links without decoding secrets twice.
    const auto end = uri.find_first_of("?#");
    const auto authority = uri.substr(5, end == std::string::npos ? std::string::npos : end - 5);
    if(authority.find('@') == std::string::npos)
    {
        if(!regMatch(authority, "^[A-Za-z0-9+/_-]+={0,2}$") || authority.size() % 4 == 1) return;
        const auto decoded = urlSafeBase64Decode(authority);
        const auto at = decoded.rfind('@');
        if(at == std::string::npos) return;
        uri = "ss://" + urlEncode(decoded.substr(0, at)) + "@" + decoded.substr(at + 1) +
            (end == std::string::npos ? "" : uri.substr(end));
    }
    share_uri::Link link;
    if(!share_uri::parse(uri, "ss", link)) return;
    auto credentials = link.userinfo;
    if(credentials.find(':') == std::string::npos)
    {
        if(!regMatch(credentials, "^[A-Za-z0-9+/_-]+={0,2}$") || credentials.size() % 4 == 1) return;
        credentials = urlSafeBase64Decode(credentials);
    }
    const auto colon = credentials.find(':');
    if(colon == std::string::npos) return;
    const auto method = credentials.substr(0, colon), password = credentials.substr(colon + 1);
    if(std::any_of(credentials.begin(), credentials.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; })) return;
    // This legacy cross-format table is not the complete SS input capability set.
    if(method != "none" && std::find(ss_ciphers.begin(), ss_ciphers.end(), method) == ss_ciphers.end()) return;
    std::string plugin, options;
    const auto plugin_value = link.get("plugin");
    if(!plugin_value.empty())
    {
        const auto separator = plugin_value.find(';');
        plugin = plugin_value.substr(0, separator);
        if(separator != std::string::npos) options = plugin_value.substr(separator + 1);
    }
    for(const auto &arg : link.query)
        if(arg.first != "plugin" && arg.first != "group") return;
    const auto group = link.get("group").empty() ? SS_DEFAULT_GROUP : urlSafeBase64Decode(link.get("group"));
    ssConstruct(node, group, link.remark, link.server, link.port, password, method, plugin, options);
}

void explodeSSD(std::string link, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    Document jsondata;
    uint32_t index = nodes.size(), listType = 0, listCount = 0;
    std::string group, port, method, password, server, remarks;
    std::string plugin, pluginopts;
    std::map<uint32_t, std::string> node_map;

    link = urlSafeBase64Decode(link.substr(6));
    jsondata.Parse(link.c_str());
    if(jsondata.HasParseError() || !jsondata.IsObject())
        return;
    if(!jsondata.HasMember("servers"))
        return;
    GetMember(jsondata, "airport", group);

    if(jsondata["servers"].IsArray())
    {
        listType = 0;
        listCount = jsondata["servers"].Size();
    }
    else if(jsondata["servers"].IsObject())
    {
        listType = 1;
        listCount = jsondata["servers"].MemberCount();
        uint32_t node_index = 0;
        for(rapidjson::Value::MemberIterator iter = jsondata["servers"].MemberBegin(); iter != jsondata["servers"].MemberEnd(); iter++)
        {
            node_map.emplace(node_index, iter->name.GetString());
            node_index++;
        }
    }
    else
        return;

    rapidjson::Value singlenode;
    for(uint32_t i = 0; i < listCount; i++)
    {
        //get default info
        port = GetMember(jsondata, "port");
        method = GetMember(jsondata, "encryption");
        password = GetMember(jsondata, "password");
        plugin = GetMember(jsondata, "plugin");
        pluginopts = GetMember(jsondata, "plugin_options");

        //get server-specific info
        switch(listType)
        {
        case 0:
            singlenode = jsondata["servers"][i];
            break;
        case 1:
            singlenode = jsondata["servers"].FindMember(node_map[i].data())->value;
            break;
        default:
            continue;
        }
        auto source_record = registry->reserve(GetMember(singlenode, "remarks"));
        singlenode["server"] >> server;
        GetMember(singlenode, "remarks", remarks);
        GetMember(singlenode, "port", port);
        GetMember(singlenode, "encryption", method);
        GetMember(singlenode, "password", password);
        GetMember(singlenode, "plugin", plugin);
        GetMember(singlenode, "plugin_options", pluginopts);

        if(port == "0")
            continue;

        Proxy node;
        ssConstruct(node, group, remarks, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSAndroid(std::string ss, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    std::string ps, password, method, server, port, group = SS_DEFAULT_GROUP;
    std::string plugin, pluginopts;

    Document json;
    auto index = nodes.size();
    //first add some extra data before parsing
    ss = "{\"nodes\":" + ss + "}";
    json.Parse(ss.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    for(uint32_t i = 0; i < json["nodes"].Size(); i++)
    {
        Proxy node;
        auto source_record = registry->reserve(GetMember(json["nodes"][i], "remarks"));
        server = GetMember(json["nodes"][i], "server");
        if(server.empty())
            continue;
        ps = GetMember(json["nodes"][i], "remarks");
        port = GetMember(json["nodes"][i], "server_port");
        if(port == "0")
            continue;
        if(ps.empty())
            ps = server + ":" + port;
        password = GetMember(json["nodes"][i], "password");
        method = GetMember(json["nodes"][i], "method");
        plugin = GetMember(json["nodes"][i], "plugin");
        pluginopts = GetMember(json["nodes"][i], "plugin_opts");

        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSConf(std::string content, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    Document json;
    std::string ps, password, method, server, port, plugin, pluginopts, group = SS_DEFAULT_GROUP;
    auto index = nodes.size();

    json.Parse(content.data());
    if(json.HasParseError() || !json.IsObject())
        return;
    const char *section = json.HasMember("version") && json.HasMember("servers") ? "servers" : "configs";
    if(!json.HasMember(section))
        return;
    GetMember(json, "remarks", group);

    for(uint32_t i = 0; i < json[section].Size(); i++)
    {
        Proxy node;
        ps = GetMember(json[section][i], "remarks");
        auto source_record = registry->reserve(ps);
        server = GetMember(json[section][i], "server");
        port = GetMember(json[section][i], "server_port");
        if(port == "0")
            continue;
        if(ps.empty())
            ps = server + ":" + port;

        password = GetMember(json[section][i], "password");
        method = GetMember(json[section][i], "method");
        server = GetMember(json[section][i], "server");
        plugin = GetMember(json[section][i], "plugin");
        pluginopts = GetMember(json[section][i], "plugin_opts");

        node.Id = index;
        ssConstruct(node, group, ps, server, port, password, method, plugin, pluginopts);
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSSR(std::string ssr, Proxy &node, SourceRegistry registry)
{
    std::string strobfs;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam;
    ssr = replaceAllDistinct(ssr.substr(6), "\r", "");
    ssr = urlSafeBase64Decode(ssr);
    if(strFind(ssr, "/?"))
    {
        strobfs = ssr.substr(ssr.find("/?") + 2);
        ssr = ssr.substr(0, ssr.find("/?"));
        group = urlSafeBase64Decode(getUrlArg(strobfs, "group"));
        remarks = urlSafeBase64Decode(getUrlArg(strobfs, "remarks"));
        obfsparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "obfsparam")), "\\s", "");
        protoparam = regReplace(urlSafeBase64Decode(getUrlArg(strobfs, "protoparam")), "\\s", "");
    }

    reserveSourceIdentity(node, registry, remarks);
    if(regGetMatch(ssr, "(\\S+):(\\d+?):(\\S+?):(\\S+?):(\\S+?):(\\S+)", 7, 0, &server, &port, &protocol, &method, &obfs, &password))
        return;
    password = urlSafeBase64Decode(password);
    if(port == "0")
        return;

    if(group.empty())
        group = SSR_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;

    if(find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin"))
    {
        ssConstruct(node, group, remarks, server, port, password, method, "", "");
    }
    else
    {
        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
    }
}

void explodeSSRConf(std::string content, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    Document json;
    std::string remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam, plugin, pluginopts;
    auto index = nodes.size();

    json.Parse(content.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    if(json.HasMember("local_port") && json.HasMember("local_address")) //single libev config
    {
        Proxy node;
        server = GetMember(json, "server");
        port = GetMember(json, "server_port");
        remarks = server + ":" + port;
        auto source_record = registry->reserve(remarks);
        method = GetMember(json, "method");
        obfs = GetMember(json, "obfs");
        protocol = GetMember(json, "protocol");
        if(find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin"))
        {
            plugin = GetMember(json, "plugin");
            pluginopts = GetMember(json, "plugin_opts");
            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts);
        }
        else
        {
            protoparam = GetMember(json, "protocol_param");
            obfsparam = GetMember(json, "obfs_param");
            ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
        }
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        return;
    }

    for(uint32_t i = 0; i < json["configs"].Size(); i++)
    {
        Proxy node;
        group = GetMember(json["configs"][i], "group");
        if(group.empty())
            group = SSR_DEFAULT_GROUP;
        remarks = GetMember(json["configs"][i], "remarks");
        auto source_record = registry->reserve(remarks);
        server = GetMember(json["configs"][i], "server");
        port = GetMember(json["configs"][i], "server_port");
        if(port == "0")
            continue;
        if(remarks.empty())
            remarks = server + ":" + port;

        password = GetMember(json["configs"][i], "password");
        method = GetMember(json["configs"][i], "method");

        protocol = GetMember(json["configs"][i], "protocol");
        protoparam = GetMember(json["configs"][i], "protocolparam");
        obfs = GetMember(json["configs"][i], "obfs");
        obfsparam = GetMember(json["configs"][i], "obfsparam");

        ssrConstruct(node, group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam);
        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeSocks(std::string link, Proxy &node)
{
    std::string group, remarks, server, port, username, password;
    if(strFind(link, "socks://")) //v2rayn socks link
    {
        if(strFind(link, "#"))
        {
            auto pos = link.find('#');
            remarks = urlDecode(link.substr(pos + 1));
            link.erase(pos);
        }
        link = urlSafeBase64Decode(link.substr(8));
        if(strFind(link, "@"))
        {
            auto userinfo = split(link, '@');
            if(userinfo.size() < 2)
                return;
            link = userinfo[1];
            userinfo = split(userinfo[0], ':');
            if(userinfo.size() < 2)
                return;
            username = userinfo[0];
            password = userinfo[1];
        }
        auto arguments = split(link, ':');
        if(arguments.size() < 2)
            return;
        server = arguments[0];
        port = arguments[1];
    }
    else if(strFind(link, "https://t.me/socks") || strFind(link, "tg://socks")) //telegram style socks link
    {
        server = getUrlArg(link, "server");
        port = getUrlArg(link, "port");
        username = urlDecode(getUrlArg(link, "user"));
        password = urlDecode(getUrlArg(link, "pass"));
        remarks = urlDecode(getUrlArg(link, "remarks"));
        group = urlDecode(getUrlArg(link, "group"));
    }
    if(group.empty())
        group = SOCKS_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;
    if(port == "0")
        return;

    socksConstruct(node, group, remarks, server, port, username, password);
}

void explodeHTTP(const std::string &link, Proxy &node)
{
    std::string group, remarks, server, port, username, password;
    server = getUrlArg(link, "server");
    port = getUrlArg(link, "port");
    username = urlDecode(getUrlArg(link, "user"));
    password = urlDecode(getUrlArg(link, "pass"));
    remarks = urlDecode(getUrlArg(link, "remarks"));
    group = urlDecode(getUrlArg(link, "group"));

    if(group.empty())
        group = HTTP_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;
    if(port == "0")
        return;

    httpConstruct(node, group, remarks, server, port, username, password, strFind(link, "/https"));
}

void explodeHTTPSub(std::string link, Proxy &node)
{
    std::string group, remarks, server, port, username, password;
    std::string addition;
    bool tls = strFind(link, "https://");
    auto pos = link.find('?');
    if(pos != std::string::npos)
    {
        addition = link.substr(pos + 1);
        link.erase(pos);
        remarks = urlDecode(getUrlArg(addition, "remarks"));
        group = urlDecode(getUrlArg(addition, "group"));
    }
    link.erase(0, link.find("://") + 3);
    link = urlSafeBase64Decode(link);
    if(strFind(link, "@"))
    {
        if(regGetMatch(link, "(.*?):(.*?)@(.*):(.*)", 5, 0, &username, &password, &server, &port))
            return;
    }
    else
    {
        if(regGetMatch(link, "(.*):(.*)", 3, 0, &server, &port))
            return;
    }

    if(group.empty())
        group = HTTP_DEFAULT_GROUP;
    if(remarks.empty())
        remarks = server + ":" + port;
    if(port == "0")
        return;

    httpConstruct(node, group, remarks, server, port, username, password, tls);
}

void explodeTrojan(std::string trojan, Proxy &node)
{
    std::string server, port, psk, addition, group, remark, host, path, network;
    tribool tfo, scv;
    trojan.erase(0, 9);
    string_size pos = trojan.rfind('#');

    if(pos != std::string::npos)
    {
        remark = urlDecode(trojan.substr(pos + 1));
        trojan.erase(pos);
    }
    pos = trojan.find('?');
    if(pos != std::string::npos)
    {
        addition = trojan.substr(pos + 1);
        trojan.erase(pos);
    }

    if(regGetMatch(trojan, "(.*?)@(.*):(.*)", 4, 0, &psk, &server, &port))
        return;
    if(port == "0")
        return;

    host = getUrlArg(addition, "sni");
    if(host.empty())
        host = getUrlArg(addition, "peer");
    tfo = getUrlArg(addition, "tfo");
    scv = getUrlArg(addition, "allowInsecure");
    group = urlDecode(getUrlArg(addition, "group"));

    if(getUrlArg(addition, "ws") == "1")
    {
        path = getUrlArg(addition, "wspath");
        network = "ws";
    }
    // support the trojan link format used by v2ryaN and X-ui.
    // format: trojan://{password}@{server}:{port}?type=ws&security=tls&path={path (urlencoded)}&sni={host}#{name}
    else if(getUrlArg(addition, "type") == "ws")
    {
        path = getUrlArg(addition, "path");
        if(path.substr(0, 3) == "%2F")
            path = urlDecode(path);
        network = "ws";
    }

    if(remark.empty())
        remark = server + ":" + port;
    if(group.empty())
        group = TROJAN_DEFAULT_GROUP;

    trojanConstruct(node, group, remark, server, port, psk, network, host, path, true, tribool(), tfo, scv);
}

static string_array splitConfigPair(const std::string &value)
{
    const auto equal = value.find('=');
    if(equal == std::string::npos) return {value};
    return {value.substr(0, equal), value.substr(equal + 1)};
}

void explodeQuan(const std::string &quan, Proxy &node)
{
    std::string strTemp, itemName, itemVal;
    std::string group = V2RAY_DEFAULT_GROUP, ps, add, port, cipher, type = "none", id, aid = "0", net = "tcp", path, host, edge, tls;
    string_array configs, vArray, headers;
    strTemp = regReplace(quan, "(.*?) = (.*)", "$1,$2");
    configs = split(strTemp, ",");

    if(configs[1] == "vmess")
    {
        if(configs.size() < 6)
            return;
        ps = trim(configs[0]);
        add = trim(configs[2]);
        port = trim(configs[3]);
        if(port == "0")
            return;
        cipher = trim(configs[4]);
        id = trim(replaceAllDistinct(configs[5], "\"", ""));

        //read link
        for(uint32_t i = 6; i < configs.size(); i++)
        {
            vArray = splitConfigPair(configs[i]);
            if(vArray.size() < 2)
                continue;
            itemName = trim(vArray[0]);
            itemVal = trim(vArray[1]);
            switch(hash_(itemName))
            {
            case "group"_hash:
                group = itemVal;
                break;
            case "over-tls"_hash:
                tls = itemVal == "true" ? "tls" : "";
                break;
            case "tls-host"_hash:
                host = itemVal;
                break;
            case "obfs-path"_hash:
                path = replaceAllDistinct(itemVal, "\"", "");
                break;
            case "obfs-header"_hash:
                headers = split(replaceAllDistinct(replaceAllDistinct(itemVal, "\"", ""), "[Rr][Nn]", "|"), "|");
                for(std::string &x : headers)
                {
                    if(regFind(x, "(?i)Host: "))
                        host = x.substr(6);
                    else if(regFind(x, "(?i)Edge: "))
                        edge = x.substr(6);
                }
                break;
            case "obfs"_hash:
                if(itemVal == "ws")
                    net = "ws";
                break;
            default:
                continue;
            }
        }
        if(path.empty())
            path = "/";

        vmessConstruct(node, group, ps, add, port, type, id, aid, net, cipher, path, host, edge, tls, "");
    }
}

void explodeNetch(std::string netch, Proxy &node, SourceRegistry registry = {})
{
    Document json;
    std::string type, group, remark, address, port, username, password, method, plugin, pluginopts;
    std::string protocol, protoparam, obfs, obfsparam, id, aid, transprot, faketype, host, edge, path, tls, sni;
    tribool udp, tfo, scv;
    netch = urlSafeBase64Decode(netch.substr(8));

    json.Parse(netch.data());
    if(json.HasParseError() || !json.IsObject())
        return;
    type = GetMember(json, "Type");
    group = GetMember(json, "Group");
    remark = GetMember(json, "Remark");
    reserveSourceIdentity(node, registry, remark);
    address = GetMember(json, "Hostname");
    udp = GetMember(json, "EnableUDP");
    tfo = GetMember(json, "EnableTFO");
    scv = GetMember(json, "AllowInsecure");
    port = GetMember(json, "Port");
    if(port == "0")
        return;
    method = GetMember(json, "EncryptMethod");
    password = GetMember(json, "Password");
    if(remark.empty())
        remark = address + ":" + port;
    switch(hash_(type))
    {
    case "SS"_hash:
        plugin = GetMember(json, "Plugin");
        pluginopts = GetMember(json, "PluginOption");
        if(group.empty())
            group = SS_DEFAULT_GROUP;
        ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
        break;
    case "SSR"_hash:
        protocol = GetMember(json, "Protocol");
        obfs = GetMember(json, "OBFS");
        if(find(ss_ciphers.begin(), ss_ciphers.end(), method) != ss_ciphers.end() && (obfs.empty() || obfs == "plain") && (protocol.empty() || protocol == "origin"))
        {
            plugin = GetMember(json, "Plugin");
            pluginopts = GetMember(json, "PluginOption");
            if(group.empty())
                group = SS_DEFAULT_GROUP;
            ssConstruct(node, group, remark, address, port, password, method, plugin, pluginopts, udp, tfo, scv);
        }
        else
        {
            protoparam = GetMember(json, "ProtocolParam");
            obfsparam = GetMember(json, "OBFSParam");
            if(group.empty())
                group = SSR_DEFAULT_GROUP;
            ssrConstruct(node, group, remark, address, port, protocol, method, obfs, password, obfsparam, protoparam, udp, tfo, scv);
        }
        break;
    case "VMess"_hash:
        id = GetMember(json, "UserID");
        aid = GetMember(json, "AlterID");
        transprot = GetMember(json, "TransferProtocol");
        faketype = GetMember(json, "FakeType");
        host = GetMember(json, "Host");
        path = GetMember(json, "Path");
        edge = GetMember(json, "Edge");
        tls = GetMember(json, "TLSSecure");
        sni = GetMember(json, "ServerName");
        if(group.empty())
            group = V2RAY_DEFAULT_GROUP;
        vmessConstruct(node, group, remark, address, port, faketype, id, aid, transprot, method, path, host, edge, tls, sni, udp, tfo, scv);
        break;
    case "Socks5"_hash:
        username = GetMember(json, "Username");
        if(group.empty())
            group = SOCKS_DEFAULT_GROUP;
        socksConstruct(node, group, remark, address, port, username, password, udp, tfo, scv);
        break;
    case "HTTP"_hash:
    case "HTTPS"_hash:
        if(group.empty())
            group = HTTP_DEFAULT_GROUP;
        httpConstruct(node, group, remark, address, port, username, password, type == "HTTPS", tfo, scv);
        break;
    case "Trojan"_hash:
        host = GetMember(json, "Host");
        path = GetMember(json, "Path");
        transprot = GetMember(json, "TransferProtocol");
        tls = GetMember(json, "TLSSecure");
        if(group.empty())
            group = TROJAN_DEFAULT_GROUP;
        trojanConstruct(node, group, remark, address, port, password, transprot, host, path, tls == "true", udp, tfo, scv);
        break;
    case "Snell"_hash:
        obfs = GetMember(json, "OBFS");
        host = GetMember(json, "Host");
        aid = GetMember(json, "SnellVersion");
        if(group.empty())
            group = SNELL_DEFAULT_GROUP;
        snellConstruct(node, group, remark, address, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv);
        break;
    default:
        return;
    }
}

static bool readOptionalClashUInt(const YAML::Node &proxy, const char *key, std::optional<uint32_t> &out)
{
    const YAML::Node value = proxy[key];
    if(!value.IsDefined()) return true;
    uint32_t parsed = 0;
    if(!value.IsScalar() || !share_uri::number(value.as<std::string>(), parsed, INT32_MAX)) return false;
    out = parsed;
    return true;
}

static const string_array tuicStringKeys = {"token", "uuid", "password", "ip", "sni", "congestion-controller",
    "udp-relay-mode", "fingerprint", "name-cert-verify", "certificate", "private-key", "bbr-profile"};
static const string_array tuicIntegerKeys = {"heartbeat-interval", "request-timeout", "max-udp-relay-packet-size",
    "max-open-streams", "cwnd", "recv-window-conn", "recv-window", "max-datagram-frame-size", "udp-over-stream-version"};
static const string_array tuicBooleanKeys = {"disable-sni", "reduce-rtt", "fast-open", "disable-mtu-discovery", "udp-over-stream"};

static bool parseTuicOptions(const YAML::Node &input, Proxy &node)
{
    const string_array common = {"name", "type", "server", "port", "udp", "tfo", "skip-cert-verify", "alpn", "dialer-proxy", "underlying-proxy"};
    for(const auto &entry : input)
    {
        const auto key = entry.first.as<std::string>();
        const auto &value = entry.second;
        if(std::find(tuicStringKeys.begin(), tuicStringKeys.end(), key) != tuicStringKeys.end())
        {
            if(!value.IsScalar()) return false;
            node.Tuic.Strings[key] = value.as<std::string>();
        }
        else if(std::find(tuicIntegerKeys.begin(), tuicIntegerKeys.end(), key) != tuicIntegerKeys.end())
        {
            uint32_t number = 0;
            if(!value.IsScalar() || !share_uri::number(value.as<std::string>(), number, INT32_MAX)) return false;
            node.Tuic.Integers[key] = number;
        }
        else if(std::find(tuicBooleanKeys.begin(), tuicBooleanKeys.end(), key) != tuicBooleanKeys.end())
        {
            if(!value.IsScalar()) return false;
            const auto text = value.as<std::string>();
            if(text != "true" && text != "false") return false;
            node.Tuic.Booleans[key] = text == "true";
        }
        else if(std::find(common.begin(), common.end(), key) == common.end()) return false;
    }
    const auto &strings = node.Tuic.Strings;
    auto has = [&](const char *key) { return strings.find(key) != strings.end(); };
    auto get = [&](const char *key) { auto p = strings.find(key); return p == strings.end() ? std::string() : p->second; };
    if(has("token"))
    {
        if(get("token").empty() || has("uuid") || has("password")) return false;
    }
    else if(!has("password") || !regMatch(get("uuid"), "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")) return false;
    if(has("udp-relay-mode") && get("udp-relay-mode") != "native" && get("udp-relay-mode") != "quic") return false;
    if(has("congestion-controller") && get("congestion-controller") != "cubic" && get("congestion-controller") != "new_reno" && get("congestion-controller") != "bbr") return false;
    if(node.Tuic.Integers.count("udp-over-stream-version") && node.Tuic.Integers.at("udp-over-stream-version") > 2) return false;
    if(input["alpn"].IsDefined())
    {
        if(!input["alpn"].IsSequence()) return false;
        for(const auto &item : input["alpn"])
        {
            if(!item.IsScalar()) return false;
            node.Alpn.push_back(item.as<std::string>());
        }
        node.AlpnSpecified = true;
    }
    for(const char *key : {"udp", "tfo", "skip-cert-verify"})
        if(input[key].IsDefined() && (!input[key].IsScalar() || (input[key].as<std::string>() != "true" && input[key].as<std::string>() != "false"))) return false;
    return true;
}

void explodeClash(Node yamlnode, std::vector<Proxy> &nodes, const SourceRegistry &registry)
{
    uint32_t index = nodes.size();
    const std::string section = yamlnode["proxies"].IsDefined() ? "proxies" : "Proxy";
    for(uint32_t i = 0; i < yamlnode[section].size(); i++)
    {
        try
        {
        std::string proxytype, ps, server, port, cipher, group, password, underlying_proxy; //common
        std::string type = "none", id, aid = "0", net = "tcp", path, host, edge, tls, sni; //vmess
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux; //ss
        std::string protocol, protoparam, obfs, obfsparam; //ssr
        std::string user; //socks
        std::string ip, ipv6, private_key, public_key, mtu; //wireguard
        std::string ports, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str,/* obfs, sni,*/ fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpn; //hysteria
        std::string obfs_password, cwnd; //hysteria2
        string_array dns_server;
        tribool udp, tfo, scv;
        Node singleproxy;
        Proxy node;
        singleproxy = yamlnode[section][i];
        singleproxy["name"] >>= ps;
        auto source_record = registry->reserve(ps);
        for(const char *key : {"dialer-proxy", "underlying-proxy"})
            if(singleproxy[key].IsDefined() && (!singleproxy[key].IsScalar() || !singleproxy[key].as<std::string>().empty())) source_record->ChainDeclared = true;
        if(singleproxy["dialer-proxy"].IsScalar()) source_record->Dependency = singleproxy["dialer-proxy"].as<std::string>();
        else if(singleproxy["underlying-proxy"].IsScalar()) source_record->Dependency = singleproxy["underlying-proxy"].as<std::string>();
        singleproxy["type"] >>= proxytype;
        singleproxy["server"] >>= server;
        singleproxy["port"] >>= port;
        singleproxy["dialer-proxy"] >>= underlying_proxy;
        if(underlying_proxy.empty()) singleproxy["underlying-proxy"] >>= underlying_proxy;
        if(port.empty() || port == "0")
            continue;
        udp = safe_as<std::string>(singleproxy["udp"]);
        tfo = safe_as<std::string>(singleproxy["tfo"].IsDefined() ? singleproxy["tfo"] : singleproxy["fast-open"]);
        scv = safe_as<std::string>(singleproxy["skip-cert-verify"]);
        if(proxytype == "anytls" || proxytype == "vless")
        {
            // Unsupported security settings cannot safely disappear from a node.
            bool unsupported = false;
            for(const char *key : {"ech-opts", "shadow-tls-opts", "restls-opts", "jls-opts", "certificate", "private-key", "name-cert-verify", "client-metadata", "smux", "packet-addr", "xudp", "disable-reuse"})
                unsupported = unsupported || singleproxy[key].IsDefined();
            if(proxytype == "anytls" && singleproxy["reality-opts"].IsDefined()) unsupported = true;
            if(proxytype == "vless" && singleproxy["encryption"].IsDefined() && !safe_as<std::string>(singleproxy["encryption"]).empty() && safe_as<std::string>(singleproxy["encryption"]) != "none") unsupported = true;
            if(unsupported)
            {
                writeLog(0, "Skipped modern Clash node: unsupported security or multiplexing option (content redacted)", LOG_LEVEL_WARNING);
                continue;
            }
        }
        switch(hash_(proxytype))
        {
        case "vmess"_hash:
            group = V2RAY_DEFAULT_GROUP;

            singleproxy["uuid"] >>= id;
            singleproxy["alterId"] >>= aid;
            singleproxy["cipher"] >>= cipher;
            net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";
            singleproxy["servername"] >>= sni;
            switch(hash_(net))
            {
            case "http"_hash:
                singleproxy["http-opts"]["path"][0] >>= path;
                singleproxy["http-opts"]["headers"]["Host"][0] >>= host;
                edge.clear();
                break;
            case "ws"_hash:
                if(singleproxy["ws-opts"].IsDefined())
                {
                    path = singleproxy["ws-opts"]["path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-opts"]["path"]) : "/";
                    singleproxy["ws-opts"]["headers"]["Host"] >>= host;
                    singleproxy["ws-opts"]["headers"]["Edge"] >>= edge;
                }
                else
                {
                    path = singleproxy["ws-path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-path"]) : "/";
                    singleproxy["ws-headers"]["Host"] >>= host;
                    singleproxy["ws-headers"]["Edge"] >>= edge;
                }
                break;
            case "h2"_hash:
                singleproxy["h2-opts"]["path"] >>= path;
                singleproxy["h2-opts"]["host"][0] >>= host;
                edge.clear();
                break;
            case "grpc"_hash:
                singleproxy["servername"] >>= host;
                singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                edge.clear();
                break;
            }
            tls = safe_as<std::string>(singleproxy["tls"]) == "true" ? "tls" : "";

            vmessConstruct(node, group, ps, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, udp, tfo, scv, tribool(), underlying_proxy);
            break;
        case "vless"_hash:
        {
            group = V2RAY_DEFAULT_GROUP;
            std::string flow, fingerprint_value, public_key_value, short_id_value;
            std::string vless_path, vless_host, vless_sni;
            std::string vless_net = singleproxy["network"].IsDefined() ? safe_as<std::string>(singleproxy["network"]) : "tcp";

            singleproxy["uuid"] >>= id;
            if(id.empty())
                continue;
            singleproxy["flow"] >>= flow;
            singleproxy["servername"] >>= vless_sni;
            singleproxy["client-fingerprint"] >>= fingerprint_value;

            bool tlssecure = safe_as<std::string>(singleproxy["tls"]) == "true";
            if(singleproxy["reality-opts"].IsDefined())
            {
                singleproxy["reality-opts"]["public-key"] >>= public_key_value;
                singleproxy["reality-opts"]["short-id"] >>= short_id_value;
                if(singleproxy["reality-opts"]["support-x25519mlkem768"].IsDefined())
                    node.RealitySupportX25519MLKEM768 = singleproxy["reality-opts"]["support-x25519mlkem768"].as<bool>();
                tlssecure = true;
            }

            switch(hash_(vless_net))
            {
            case "tcp"_hash:
                break;
            case "ws"_hash:
                if(singleproxy["ws-opts"].IsDefined())
                {
                    vless_path = singleproxy["ws-opts"]["path"].IsDefined() ? safe_as<std::string>(singleproxy["ws-opts"]["path"]) : "/";
                    singleproxy["ws-opts"]["headers"]["Host"] >>= vless_host;
                }
                break;
            case "grpc"_hash:
                singleproxy["grpc-opts"]["grpc-service-name"] >>= vless_path;
                break;
            case "h2"_hash:
                singleproxy["h2-opts"]["path"] >>= vless_path;
                if(singleproxy["h2-opts"]["host"].IsSequence() && singleproxy["h2-opts"]["host"].size())
                    singleproxy["h2-opts"]["host"][0] >>= vless_host;
                break;
            case "http"_hash:
                if(singleproxy["http-opts"]["path"].IsSequence() && singleproxy["http-opts"]["path"].size())
                    singleproxy["http-opts"]["path"][0] >>= vless_path;
                if(singleproxy["http-opts"]["headers"]["Host"].IsSequence() && singleproxy["http-opts"]["headers"]["Host"].size())
                    singleproxy["http-opts"]["headers"]["Host"][0] >>= vless_host;
                break;
            default:
                continue;
            }

            vlessConstruct(node, group, ps, server, port, id, flow, vless_net, vless_path, vless_host, tlssecure, vless_sni, fingerprint_value, public_key_value, short_id_value, udp, tfo, scv, underlying_proxy);
            if(singleproxy["alpn"].IsSequence())
            {
                singleproxy["alpn"] >>= node.Alpn;
                node.AlpnSpecified = true;
            }
            singleproxy["packet-encoding"] >>= node.PacketEncoding;
            singleproxy["fingerprint"] >>= node.CertificateFingerprint;
            break;
        }
        case "ss"_hash:
            group = SS_DEFAULT_GROUP;

            singleproxy["cipher"] >>= cipher;
            singleproxy["password"] >>= password;
            if(singleproxy["plugin"].IsDefined())
            {
                switch(hash_(safe_as<std::string>(singleproxy["plugin"])))
                {
                case "obfs"_hash:
                    plugin = "obfs-local";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                        singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                    }
                    break;
                case "v2ray-plugin"_hash:
                    plugin = "v2ray-plugin";
                    if(singleproxy["plugin-opts"].IsDefined())
                    {
                        singleproxy["plugin-opts"]["mode"] >>= pluginopts_mode;
                        singleproxy["plugin-opts"]["host"] >>= pluginopts_host;
                        tls = safe_as<bool>(singleproxy["plugin-opts"]["tls"]) ? "tls;" : "";
                        singleproxy["plugin-opts"]["path"] >>= path;
                        pluginopts_mux = safe_as<bool>(singleproxy["plugin-opts"]["mux"]) ? "mux;" : "";
                    }
                    break;
                default:
                    writeLog(0, "Skipped SS node: unsupported plugin (content redacted)", LOG_LEVEL_WARNING);
                    continue;
                }
            }
            else if(singleproxy["obfs"].IsDefined())
            {
                plugin = "obfs-local";
                singleproxy["obfs"] >>= pluginopts_mode;
                singleproxy["obfs-host"] >>= pluginopts_host;
            }
            else
                plugin.clear();

            switch(hash_(plugin))
            {
            case "simple-obfs"_hash:
            case "obfs-local"_hash:
                pluginopts = "obfs=" + pluginopts_mode;
                pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
                break;
            case "v2ray-plugin"_hash:
                pluginopts = "mode=" + pluginopts_mode + ";" + tls + pluginopts_mux;
                if(!pluginopts_host.empty())
                    pluginopts += "host=" + pluginopts_host + ";";
                if(!path.empty())
                    pluginopts += "path=" + path + ";";
                break;
            }

            //support for go-shadowsocks2
            if(cipher == "AEAD_CHACHA20_POLY1305")
                cipher = "chacha20-ietf-poly1305";
            else if(strFind(cipher, "AEAD"))
            {
                cipher = replaceAllDistinct(replaceAllDistinct(cipher, "AEAD_", ""), "_", "-");
                std::transform(cipher.begin(), cipher.end(), cipher.begin(), ::tolower);
            }

            ssConstruct(node, group, ps, server, port, password, cipher, plugin, pluginopts, udp, tfo, scv,  tribool(), underlying_proxy);
            break;
        case "socks5"_hash:
            group = SOCKS_DEFAULT_GROUP;

            singleproxy["username"] >>= user;
            singleproxy["password"] >>= password;

            socksConstruct(node, group, ps, server, port, user, password, tribool(),  tribool(),  tribool(), underlying_proxy);
            break;
        case "ssr"_hash:
            group = SSR_DEFAULT_GROUP;

            singleproxy["cipher"] >>= cipher;
            if(cipher == "dummy") cipher = "none";
            singleproxy["password"] >>= password;
            singleproxy["protocol"] >>= protocol;
            singleproxy["obfs"] >>= obfs;
            if(singleproxy["protocol-param"].IsDefined())
                singleproxy["protocol-param"] >>= protoparam;
            else
                singleproxy["protocolparam"] >>= protoparam;
            if(singleproxy["obfs-param"].IsDefined())
                singleproxy["obfs-param"] >>= obfsparam;
            else
                singleproxy["obfsparam"] >>= obfsparam;

            ssrConstruct(node, group, ps, server, port, protocol, cipher, obfs, password, obfsparam, protoparam, udp, tfo, scv, underlying_proxy);
            break;
        case "http"_hash:
            group = HTTP_DEFAULT_GROUP;

            singleproxy["username"] >>= user;
            singleproxy["password"] >>= password;
            singleproxy["tls"] >>= tls;

            httpConstruct(node, group, ps, server, port, user, password, tls == "true", tfo, scv, tribool(), underlying_proxy);
            break;
        case "trojan"_hash:
            group = TROJAN_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= host;
            singleproxy["network"] >>= net;
            switch(hash_(net))
            {
            case "grpc"_hash:
                singleproxy["grpc-opts"]["grpc-service-name"] >>= path;
                break;
            case "ws"_hash:
                singleproxy["ws-opts"]["path"] >>= path;
                break;
            default:
                net = "tcp";
                path.clear();
                break;
            }

            trojanConstruct(node, group, ps, server, port, password, net, host, path, true, udp, tfo, scv, tribool(),  underlying_proxy);
            break;
        case "snell"_hash:
            group = SNELL_DEFAULT_GROUP;
            singleproxy["psk"] >> password;
            singleproxy["obfs-opts"]["mode"] >>= obfs;
            singleproxy["obfs-opts"]["host"] >>= host;
            singleproxy["version"] >>= aid;

            snellConstruct(node, group, ps, server, port, password, obfs, host, to_int(aid, 0), udp, tfo, scv, underlying_proxy);
            break;
        case "wireguard"_hash:
            group = WG_DEFAULT_GROUP;
            singleproxy["public-key"] >>= public_key;
            singleproxy["private-key"] >>= private_key;
            singleproxy["dns"] >>= dns_server;
            singleproxy["mtu"] >>= mtu;
            singleproxy["preshared-key"] >>= password;
            singleproxy["ip"] >>= ip;
            singleproxy["ipv6"] >>= ipv6;

            wireguardConstruct(node, group, ps, server, port, ip, ipv6, private_key, public_key, password, dns_server, mtu, "0", "", "", udp, underlying_proxy);
            break;
        case "hysteria"_hash:
            group = HYSTERIA_DEFAULT_GROUP;
            singleproxy["ports"] >>= ports;
            singleproxy["protocol"] >>= protocol;
            singleproxy["obfs-protocol"] >>= obfs_protocol;
            singleproxy["up"] >>= up;
            singleproxy["up-speed"] >>= up_speed;
            singleproxy["down"] >>= down;
            singleproxy["down-speed"] >>= down_speed;
            singleproxy["auth"] >>= auth;
            singleproxy["auth-str"] >>= auth_str;
            if (auth_str.empty())
                singleproxy["auth_str"] >>= auth_str;
            singleproxy["obfs"] >>= obfs;
            singleproxy["sni"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            singleproxy["ca"] >>= ca;
            singleproxy["ca-str"] >>= ca_str;
            singleproxy["recv-window-conn"] >>= recv_window_conn;
            singleproxy["recv-window"] >>= recv_window;
            singleproxy["disable-mtu-discovery"] >>= disable_mtu_discovery;
            if (disable_mtu_discovery.empty())
                singleproxy["disable_mtu_discovery"] >>= disable_mtu_discovery;
            singleproxy["hop-interval"] >>= hop_interval;

            hysteriaConstruct(node, group, ps, server, port, ports, protocol, obfs_protocol, up, up_speed, down, down_speed, auth, auth_str, obfs, sni, fingerprint, ca, ca_str, recv_window_conn, recv_window, disable_mtu_discovery, hop_interval, alpn, tfo, scv, underlying_proxy);
            break;
        case "hysteria2"_hash:
            group = HYSTERIA2_DEFAULT_GROUP;
            singleproxy["ports"] >>= ports;
            singleproxy["up"] >>= up;
            singleproxy["down"] >>= down;
            singleproxy["password"] >>= password;
            if (password.empty())
                singleproxy["auth"] >>= password; 
            singleproxy["obfs"] >>= obfs;
            singleproxy["obfs-password"] >>= obfs_password;
            singleproxy["sni"] >>= sni;
            singleproxy["fingerprint"] >>= fingerprint;
            if (singleproxy["alpn"].IsSequence())
                singleproxy["alpn"][0] >>= alpn;
            else
                singleproxy["alpn"] >>= alpn;
            singleproxy["ca"] >>= ca;
            singleproxy["ca-str"] >>= ca_str;
            singleproxy["cwnd"] >>= cwnd;
            singleproxy["hop-interval"] >>= hop_interval;

            hysteria2Construct(node, group, ps, server, port, ports, up, down, password, obfs, obfs_password, sni, fingerprint, alpn, ca, ca_str, cwnd, hop_interval, tfo, scv, underlying_proxy);
            node.UDP = udp;
            if(singleproxy["alpn"].IsSequence())
            {
                singleproxy["alpn"] >>= node.Alpn;
                node.AlpnSpecified = true;
            }
            break;
        case "tuic"_hash:
        {
            uint32_t port_number = 0;
            if(server.empty() || !share_uri::number(port, port_number, 65535) || port_number == 0 || !parseTuicOptions(singleproxy, node))
            {
                writeLog(0, "Skipped TUIC node: invalid or unsupported option (content redacted)", LOG_LEVEL_WARNING);
                continue;
            }
            // TUIC fast-open is a QUIC option; it must not become TCP tfo.
            tfo = safe_as<std::string>(singleproxy["tfo"]);
            commonConstruct(node, ProxyType::TUIC, TUIC_DEFAULT_GROUP, ps, server, port, udp, tfo, scv, tribool(), underlying_proxy);
            node.TLSSecure = true;
            break;
        }
        case "anytls"_hash:
            group = ANYTLS_DEFAULT_GROUP;
            singleproxy["password"] >>= password;
            singleproxy["sni"] >>= sni;

            anyTLSConstruct(node, group, ps, server, port, password, sni, udp, tfo, scv, underlying_proxy);
            singleproxy["client-fingerprint"] >>= node.ClientFingerprint;
            singleproxy["fingerprint"] >>= node.Fingerprint;
            if(singleproxy["alpn"].IsSequence())
            {
                singleproxy["alpn"] >>= node.Alpn;
                node.AlpnSpecified = true;
            }
            else if(singleproxy["alpn"].IsDefined())
                node.Alpn = split(safe_as<std::string>(singleproxy["alpn"]), ",");
            if(!readOptionalClashUInt(singleproxy, "idle-session-check-interval", node.IdleSessionCheckInterval) ||
               !readOptionalClashUInt(singleproxy, "idle-session-timeout", node.IdleSessionTimeout) ||
               !readOptionalClashUInt(singleproxy, "min-idle-session", node.MinIdleSession))
            {
                writeLog(0, "Skipped AnyTLS node: invalid idle-session parameter", LOG_LEVEL_WARNING);
                continue;
            }
            break;
        default:
            writeLog(0, "Skipped unsupported Clash protocol (content redacted)", LOG_LEVEL_WARNING);
            continue;
        }

        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
        }
        catch(const YAML::Exception &)
        {
            writeLog(0, "Skipped malformed Clash node (content redacted)", LOG_LEVEL_WARNING);
        }
    }
}

void explodeVless(const std::string &uri, Proxy &node)
{
    share_uri::Link link;
    tribool udp, tfo, scv;
    if(!share_uri::parse(uri, "vless", link) ||
       !regMatch(link.userinfo, "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$") ||
       !link.boolean("udp", udp) || !link.boolean("tfo", tfo) || !link.boolean("allowInsecure", scv)) return;
    tribool insecure;
    if(!link.boolean("insecure", insecure) || (!scv.is_undef() && !insecure.is_undef() && scv != insecure)) return;
    scv.define(insecure);
    const string_array accepted = {"type", "security", "encryption", "flow", "sni", "fp", "pbk", "sid",
        "host", "path", "serviceName", "mode", "headerType", "alpn", "packet-encoding", "udp", "tfo", "allowInsecure", "insecure"};
    for(const auto &entry : link.query)
        if(std::find(accepted.begin(), accepted.end(), entry.first) == accepted.end()) return;
    const auto encryption = link.get("encryption");
    if(!encryption.empty() && encryption != "none") return;
    auto network = link.get("type");
    if(network.empty()) network = "tcp";
    // Xray share links call HTTP/2 "http"; Mihomo calls that transport "h2".
    if(network == "http") network = "h2";
    const auto security = link.get("security");
    if(!security.empty() && security != "none" && security != "tls" && security != "reality") return;
    const bool tls = security == "tls" || security == "reality";
    if(!link.get("headerType").empty() && link.get("headerType") != "none") return;
    if(!link.get("mode").empty() && !(network == "grpc" && link.get("mode") == "gun")) return;
    const auto flow = link.get("flow");
    if(!flow.empty() && (flow != "xtls-rprx-vision" || network != "tcp" || !tls)) return;
    const auto pbk = link.get("pbk"), sid = link.get("sid");
    if(security == "reality")
    {
        if(!regMatch(pbk, "^[A-Za-z0-9_-]{43}$") || sid.size() > 16 || sid.size() % 2 ||
           !std::all_of(sid.begin(), sid.end(), [](unsigned char c) { return share_uri::hex(c) >= 0; })) return;
    }
    else if(!pbk.empty() || !sid.empty()) return;
    if(!tls && (!link.get("sni").empty() || !link.get("fp").empty() || !link.get("alpn").empty() || !scv.is_undef())) return;
    const auto packet = link.get("packet-encoding");
    if(!packet.empty() && packet != "xudp" && packet != "packetaddr" && packet != "packet") return;
    std::string path = link.get("path"), host = link.get("host");
    if(network == "grpc")
    {
        if(!path.empty() || !host.empty()) return;
        path = link.get("serviceName");
    }
    else if(!link.get("serviceName").empty()) return;
    if(network == "tcp")
    {
        if(!path.empty() || !host.empty()) return;
    }
    else if(network != "ws" && network != "grpc" && network != "h2" && network != "http") return;
    if(host.find(',') != std::string::npos) return;
    vlessConstruct(node, V2RAY_DEFAULT_GROUP, link.remark, link.server, link.port, link.userinfo,
        flow, network, path, host, tls,
        tls && link.get("sni").empty() ? link.server : link.get("sni"),
        tls && link.get("fp").empty() ? "chrome" : link.get("fp"), pbk, sid, udp, tfo, scv, "");
    node.PacketEncoding = packet;
    if(!link.get("alpn").empty()) node.Alpn = split(link.get("alpn"), ",");
}

void explodeStdVMess(std::string vmess, Proxy &node)
{
    std::string add, port, type, id, aid, net, path, host, tls, remarks;
    std::string addition;
    vmess = vmess.substr(8);
    string_size pos;

    pos = vmess.rfind('#');
    if(pos != std::string::npos)
    {
        remarks = urlDecode(vmess.substr(pos + 1));
        vmess.erase(pos);
    }
    const std::string stdvmess_matcher = R"(^([a-z]+)(?:\+([a-z]+))?:([\da-f]{4}(?:[\da-f]{4}-){4}[\da-f]{12})-(\d+)@(.+):(\d+)(?:\/?\?(.*))?$)";
    if(regGetMatch(vmess, stdvmess_matcher, 8, 0, &net, &tls, &id, &aid, &add, &port, &addition))
        return;

    switch(hash_(net))
    {
    case "tcp"_hash:
    case "kcp"_hash:
        type = getUrlArg(addition, "type");
        break;
    case "http"_hash:
    case "ws"_hash:
        host = getUrlArg(addition, "host");
        path = getUrlArg(addition, "path");
        break;
    case "quic"_hash:
        type = getUrlArg(addition, "security");
        host = getUrlArg(addition, "type");
        path = getUrlArg(addition, "key");
        break;
    default:
        return;
    }

    if(remarks.empty())
        remarks = add + ":" + port;

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, "auto", path, host, "", tls, "");
}

void explodeShadowrocket(std::string rocket, Proxy &node)
{
    std::string add, port, type, id, aid, net = "tcp", path, host, tls, cipher, remarks;
    std::string obfs; //for other style of link
    std::string addition;
    rocket = rocket.substr(8);

    string_size pos = rocket.find('?');
    addition = rocket.substr(pos + 1);
    rocket.erase(pos);

    if(regGetMatch(urlSafeBase64Decode(rocket), "(.*?):(.*)@(.*):(.*)", 5, 0, &cipher, &id, &add, &port))
        return;
    if(port == "0")
        return;
    remarks = urlDecode(getUrlArg(addition, "remarks"));
    obfs = getUrlArg(addition, "obfs");
    if(!obfs.empty())
    {
        if(obfs == "websocket")
        {
            net = "ws";
            host = getUrlArg(addition, "obfsParam");
            path = getUrlArg(addition, "path");
        }
    }
    else
    {
        net = getUrlArg(addition, "network");
        host = getUrlArg(addition, "wsHost");
        path = getUrlArg(addition, "wspath");
    }
    tls = getUrlArg(addition, "tls") == "1" ? "tls" : "";
    aid = getUrlArg(addition, "aid");

    if(aid.empty())
        aid = "0";

    if(remarks.empty())
        remarks = add + ":" + port;

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "");
}

void explodeKitsunebi(std::string kit, Proxy &node)
{
    std::string add, port, type, id, aid = "0", net = "tcp", path, host, tls, cipher = "auto", remarks;
    std::string addition;
    string_size pos;
    kit = kit.substr(9);

    pos = kit.find('#');
    if(pos != std::string::npos)
    {
        remarks = kit.substr(pos + 1);
        kit = kit.substr(0, pos);
    }

    pos = kit.find('?');
    addition = kit.substr(pos + 1);
    kit = kit.substr(0, pos);

    if(regGetMatch(kit, "(.*?)@(.*):(.*)", 4, 0, &id, &add, &port))
        return;
    pos = port.find('/');
    if(pos != std::string::npos)
    {
        path = port.substr(pos);
        port.erase(pos);
    }
    if(port == "0")
        return;
    net = getUrlArg(addition, "network");
    tls = getUrlArg(addition, "tls") == "true" ? "tls" : "";
    host = getUrlArg(addition, "ws.host");

    if(remarks.empty())
        remarks = add + ":" + port;

    vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, add, port, type, id, aid, net, cipher, path, host, "", tls, "");
}


void explodeStdHysteria2(std::string uri, Proxy &node)
{
    share_uri::Link link;
    tribool scv, udp, tfo;
    if(!share_uri::parse(uri, "hysteria2", link, "443", true, true) ||
       !link.boolean("insecure", scv) || !link.boolean("udp", udp) || !link.boolean("tfo", tfo)) return;
    const string_array accepted = {"sni", "insecure", "obfs", "obfs-password", "pinSHA256", "alpn", "up", "down", "ports", "udp", "tfo", "hop-interval", "password"};
    for(const auto &entry : link.query)
        if(std::find(accepted.begin(), accepted.end(), entry.first) == accepted.end()) return;
    const auto password = link.userinfo.empty() ? link.get("password") : link.userinfo;
    if(password.empty() || (!link.userinfo.empty() && !link.get("password").empty() && link.userinfo != link.get("password"))) return;
    if(!link.get("obfs").empty() && link.get("obfs") != "salamander") return;
    auto ports = link.ports;
    uint32_t number = 0;
    if(!link.get("ports").empty())
    {
        if(!share_uri::portRanges(link.get("ports"), number) || (!ports.empty() && ports != link.get("ports"))) return;
        ports = link.get("ports");
    }
    for(const auto *key : {"up", "down", "hop-interval"})
        if(!link.get(key).empty() && !share_uri::number(link.get(key), number, INT32_MAX)) return;
    hysteria2Construct(node, HYSTERIA2_DEFAULT_GROUP, link.remark, link.server, link.port, ports,
        link.get("up"), link.get("down"), password, link.get("obfs"), link.get("obfs-password"), link.get("sni"),
        link.get("pinSHA256"), "", "", "", "", link.get("hop-interval"), tfo, scv, "");
    node.Up = link.get("up"); node.Down = link.get("down");
    node.UDP = udp;
    if(link.query.count("alpn"))
    {
        node.Alpn = split(link.get("alpn"), ",");
        node.AlpnSpecified = true;
    }
}

void explodeHysteria2(std::string uri, Proxy &node)
{
    if(startsWith(uri, "hy2://")) uri.replace(0, 6, "hysteria2://");
    explodeStdHysteria2(uri, node);
}

void explodeTuic(const std::string &uri, Proxy &node)
{
    share_uri::Link link;
    if(!share_uri::parse(uri, "tuic", link)) return;
    YAML::Node config;
    config["name"] = link.remark;
    config["type"] = "tuic";
    config["server"] = link.server;
    config["port"] = link.port;
    const auto colon = link.raw_userinfo.find(':');
    if(colon != std::string::npos)
    {
        std::string uuid, password;
        if(!share_uri::decode(link.raw_userinfo.substr(0, colon), uuid) ||
           !share_uri::decode(link.raw_userinfo.substr(colon + 1), password)) return;
        config["uuid"] = uuid;
        config["password"] = password;
    }
    else config["token"] = link.userinfo;
    const std::map<std::string, std::string> aliases = {
        {"congestion_control", "congestion-controller"}, {"udp_relay_mode", "udp-relay-mode"},
        {"disable_sni", "disable-sni"}, {"reduce_rtt", "reduce-rtt"},
        {"allow_insecure", "skip-cert-verify"}, {"insecure", "skip-cert-verify"}, {"underlying-proxy", "dialer-proxy"}};
    std::set<std::string> seen;
    for(const auto &entry : link.query)
    {
        auto alias = aliases.find(entry.first);
        const auto key = alias == aliases.end() ? entry.first : alias->second;
        if(!seen.insert(key).second || key == "token" || key == "uuid" || key == "password" ||
           key == "name" || key == "type" || key == "server" || key == "port") return;
        if(key == "alpn")
        {
            config[key] = split(entry.second, ",");
        }
        else if(std::find(tuicBooleanKeys.begin(), tuicBooleanKeys.end(), key) != tuicBooleanKeys.end() || key == "udp" || key == "tfo" || key == "skip-cert-verify")
        {
            tribool value;
            if(!link.boolean(entry.first, value)) return;
            config[key] = value.get();
        }
        else config[key] = entry.second;
    }
    if(!parseTuicOptions(config, node)) return;
    const tribool udp(safe_as<std::string>(config["udp"])), tfo(safe_as<std::string>(config["tfo"])), scv(safe_as<std::string>(config["skip-cert-verify"]));
    commonConstruct(node, ProxyType::TUIC, TUIC_DEFAULT_GROUP, link.remark, link.server, link.port, udp, tfo, scv, tribool(), safe_as<std::string>(config["dialer-proxy"]));
    node.TLSSecure = true;
}

void explodeAnyTLS(std::string anytls, Proxy &node)
{
    share_uri::Link link;
    tribool udp, tfo, scv;
    if(!share_uri::parse(anytls, "anytls", link, "443") ||
       !link.boolean("udp", udp) || !link.boolean("tfo", tfo) || !link.boolean("insecure", scv))
        return;
    const string_array accepted = {"sni", "peer", "udp", "tfo", "insecure", "fp", "client-fingerprint", "fingerprint", "alpn"};
    for(const auto &entry : link.query)
        if(std::find(accepted.begin(), accepted.end(), entry.first) == accepted.end()) return;
    if(!link.get("sni").empty() && !link.get("peer").empty() && link.get("sni") != link.get("peer")) return;
    if(!link.get("fp").empty() && !link.get("client-fingerprint").empty() && link.get("fp") != link.get("client-fingerprint")) return;
    const auto sni = link.get("sni").empty() ? link.get("peer") : link.get("sni");
    anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, link.remark, link.server, link.port, link.userinfo, sni, udp, tfo, scv, "");
    node.ClientFingerprint = link.get("client-fingerprint").empty() ? link.get("fp") : link.get("client-fingerprint");
    node.Fingerprint = link.get("fingerprint");
    if(!link.get("alpn").empty()) node.Alpn = split(link.get("alpn"), ",");
}

// peer = (public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, allowed-ips = "0.0.0.0/0, ::/0", endpoint = engage.cloudflareclient.com:2408, client-id = 139/184/125),(public-key = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=, endpoint = engage.cloudflareclient.com:2408)
void parsePeers(Proxy &node, const std::string &data)
{
    auto peers = regGetAllMatch(data, R"(\((.*?)\))", true);
    if(peers.empty())
        return;
    auto peer = peers[0];
    auto peerdata = regGetAllMatch(peer, R"(([a-z-]+) ?= ?([^" ),]+|".*?"),? ?)", true);
    if(peerdata.size() % 2 != 0)
        return;
    for(size_t i = 0; i < peerdata.size(); i += 2)
    {
        auto key = peerdata[i];
        auto val = peerdata[i + 1];
        switch(hash_(key))
        {
        case "public-key"_hash:
            node.PublicKey = val;
            break;
        case "endpoint"_hash:
            node.Hostname = val.substr(0, val.rfind(':'));
            node.Port = to_int(val.substr(val.rfind(':') + 1));
            break;
        case "client-id"_hash:
            node.ClientId = val;
            break;
        case "allowed-ips"_hash:
            node.AllowedIPs = trimOf(val, '"');
            break;
        default:
            break;
        }
    }
}

bool explodeSurge(std::string surge, std::vector<Proxy> &nodes, const SourceRegistry &registry)
{
    std::multimap<std::string, std::string> proxies;
    uint32_t i, index = nodes.size();
    INIReader ini;

    /*
    if(!strFind(surge, "[Proxy]"))
        return false;
    */

    ini.store_isolated_line = true;
    ini.keep_empty_section = false;
    ini.allow_dup_section_titles = true;
    ini.set_isolated_items_section("Proxy");
    ini.add_direct_save_section("Proxy");
    if(surge.find("[Proxy]") != surge.npos)
        surge = regReplace(surge, R"(^[\S\s]*?\[)", "[", false);
    ini.parse(surge);

    if(!ini.section_exist("Proxy"))
        return false;
    ini.enter_section("Proxy");
    ini.get_items(proxies);

    const std::string proxystr = "(.*?)\\s*=\\s*(.*)";

    for(auto &x : proxies)
    {
        std::string remarks, server, port, method, username, password; //common
        std::string plugin, pluginopts, pluginopts_mode, pluginopts_host, mod_url, mod_md5; //ss
        std::string id, net, tls, host, edge, path; //v2
        std::string protocol, protoparam; //ssr
        std::string section, ip, ipv6, private_key, public_key, mtu, test_url, client_id, peer, keepalive; //wireguard
        string_array dns_servers;
        string_multimap wireguard_config;
        std::string version, aead = "1";
        std::string itemName, itemVal, config;
        std::vector<std::string> configs, vArray, headers, header;
        tribool udp, tfo, scv, tls13;
        Proxy node;

        /*
        remarks = regReplace(x.second, proxystr, "$1");
        configs = split(regReplace(x.second, proxystr, "$2"), ",");
        */
        regGetMatch(x.second, proxystr, 3, 0, &remarks, &config);
        configs = split(config, ",");
        if(!configs.empty() && (trim(configs[0]) == "direct" || trim(configs[0]) == "reject" || trim(configs[0]) == "reject-tinygif")) continue;
        // QX uses a protocol keyword on the left and tag= for the source name.
        std::string source_name = remarks;
        if(remarks == "shadowsocks" || remarks == "vmess" || remarks == "trojan" || remarks == "anytls" || remarks == "http")
            for(const auto &part : split(config, ","))
                if(startsWith(trim(part), "tag=")) source_name = trim(part).substr(4);
        auto source_record = registry->reserve(source_name);
        configs = split(config, ",");
        if(configs.size() < 3)
            continue;
        switch(hash_(configs[0]))
        {
        case "direct"_hash:
        case "reject"_hash:
        case "reject-tinygif"_hash:
            continue;
        case "custom"_hash: //surge 2 style custom proxy
            //remove module detection to speed up parsing and compatible with broken module
            /*
            mod_url = trim(configs[5]);
            if(parsedMD5.count(mod_url) > 0)
            {
                mod_md5 = parsedMD5[mod_url]; //read calculated MD5 from map
            }
            else
            {
                mod_md5 = getMD5(webGet(mod_url)); //retrieve module and calculate MD5
                parsedMD5.insert(std::pair<std::string, std::string>(mod_url, mod_md5)); //save unrecognized module MD5 to map
            }
            */

            //if(mod_md5 == modSSMD5) //is SSEncrypt module
        {
            if(configs.size() < 5)
                continue;
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            method = trim(configs[3]);
            password = trim(configs[4]);

            for(i = 6; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "obfs"_hash:
                    plugin = "simple-obfs";
                    pluginopts_mode = itemVal;
                    break;
                case "obfs-host"_hash:
                    pluginopts_host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                default:
                    continue;
                }
            }
            if(!plugin.empty())
            {
                pluginopts = "obfs=" + pluginopts_mode;
                pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
            }

            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv);
        }
            //else
            //    continue;
        break;
        case "ss"_hash: //surge 3 style ss proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "encrypt-method"_hash:
                    method = itemVal;
                    break;
                case "password"_hash:
                    password = itemVal;
                    break;
                case "obfs"_hash:
                    plugin = "simple-obfs";
                    pluginopts_mode = itemVal;
                    break;
                case "obfs-host"_hash:
                    pluginopts_host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                default:
                    continue;
                }
            }
            if(!plugin.empty())
            {
                pluginopts = "obfs=" + pluginopts_mode;
                pluginopts += pluginopts_host.empty() ? "" : ";obfs-host=" + pluginopts_host;
            }

            ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv);
            break;
        case "socks5"_hash: //surge 3 style socks5 proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            if(configs.size() >= 5)
            {
                username = trim(configs[3]);
                password = trim(configs[4]);
            }
            for(i = 5; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                default:
                    continue;
                }
            }
            socksConstruct(node, SOCKS_DEFAULT_GROUP, remarks, server, port, username, password, udp, tfo, scv);
            break;
        case "vmess"_hash: //surge 4 style vmess proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            net = "tcp";
            method = "auto";

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "username"_hash:
                    id = itemVal;
                    break;
                case "ws"_hash:
                    net = itemVal == "true" ? "ws" : "tcp";
                    break;
                case "tls"_hash:
                    tls = itemVal == "true" ? "tls" : "";
                    break;
                case "ws-path"_hash:
                    path = itemVal;
                    break;
                case "obfs-host"_hash:
                    host = itemVal;
                    break;
                case "ws-headers"_hash:
                    headers = split(itemVal, "|");
                    for(auto &y : headers)
                    {
                        header = split(trim(y), ":");
                        if(header.size() != 2)
                            continue;
                        else if(regMatch(header[0], "(?i)host"))
                            host = trimQuote(header[1]);
                        else if(regMatch(header[0], "(?i)edge"))
                            edge = trimQuote(header[1]);
                    }
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "tls13"_hash:
                    tls13 = itemVal;
                    break;
                case "vmess-aead"_hash:
                    aead = itemVal == "true" ? "0" : "1";
                default:
                    continue;
                }
            }

            vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, edge, tls, "", udp, tfo, scv, tls13);
            break;
        case "http"_hash: //http proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;
            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() < 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "username"_hash:
                    username = itemVal;
                    break;
                case "password"_hash:
                    password = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                default:
                    continue;
                }
            }
            httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, false, tfo, scv);
            break;
        case "trojan"_hash: // surge 4 style trojan proxy
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "password"_hash:
                    password = itemVal;
                    break;
                case "sni"_hash:
                    host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                default:
                    continue;
                }
            }

            trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", true, udp, tfo, scv);
            break;
        case "snell"_hash:
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "psk"_hash:
                    password = itemVal;
                    break;
                case "obfs"_hash:
                    plugin = itemVal;
                    break;
                case "obfs-host"_hash:
                    host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                case "version"_hash:
                    version = itemVal;
                    break;
                default:
                    continue;
                }
            }

            snellConstruct(node, SNELL_DEFAULT_GROUP, remarks, server, port, password, plugin, host, to_int(version, 0), udp, tfo, scv);
            break;
        case "wireguard"_hash:
            for (i = 1; i < configs.size(); i++)
            {
                vArray = splitConfigPair(trim(configs[i]));
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "section-name"_hash:
                    section = itemVal;
                    break;
                case "test-url"_hash:
                    test_url = itemVal;
                    break;
                }
            }
            if(section.empty())
                continue;
            ini.get_items("WireGuard " + section, wireguard_config);
            if(wireguard_config.empty())
                continue;

            for (auto &c : wireguard_config)
            {
                itemName = trim(c.first);
                itemVal = trim(c.second);
                switch(hash_(itemName))
                {
                case "self-ip"_hash:
                    ip = itemVal;
                    break;
                case "self-ip-v6"_hash:
                    ipv6 = itemVal;
                    break;
                case "private-key"_hash:
                    private_key = itemVal;
                    break;
                case "dns-server"_hash:
                    vArray = split(itemVal, ",");
                    for (auto &y : vArray)
                        dns_servers.emplace_back(trim(y));
                    break;
                case "mtu"_hash:
                    mtu = itemVal;
                    break;
                case "peer"_hash:
                    peer = itemVal;
                    break;
                case "keepalive"_hash:
                    keepalive = itemVal;
                    break;
                }
            }

            wireguardConstruct(node, WG_DEFAULT_GROUP, remarks, "", "0", ip, ipv6, private_key, "", "", dns_servers, mtu, keepalive, test_url, "", udp, "");
            parsePeers(node, peer);
            break;
        case "anytls"_hash:
            server = trim(configs[1]);
            port = trim(configs[2]);
            if(port == "0")
                continue;

            for(i = 3; i < configs.size(); i++)
            {
                vArray = splitConfigPair(configs[i]);
                if(vArray.size() != 2)
                    continue;
                itemName = trim(vArray[0]);
                itemVal = trim(vArray[1]);
                switch(hash_(itemName))
                {
                case "password"_hash:
                    password = itemVal;
                    break;
                case "sni"_hash:
                    host = itemVal;
                    break;
                case "udp-relay"_hash:
                    udp = itemVal;
                    break;
                case "tfo"_hash:
                    tfo = itemVal;
                    break;
                case "skip-cert-verify"_hash:
                    scv = itemVal;
                    break;
                }
            }

            anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, server, port, password, host, udp, tfo, scv, "");
            break;
        default:
            switch(hash_(remarks))
            {
            case "shadowsocks"_hash: //quantumult x style ss/ssr link
                server = trim(configs[0].substr(0, configs[0].rfind(":")));
                port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                if(port == "0")
                    continue;

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitConfigPair(trim(configs[i]));
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "method"_hash:
                        method = itemVal;
                        break;
                    case "password"_hash:
                        password = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "ssr-protocol"_hash:
                        protocol = itemVal;
                        break;
                    case "ssr-protocol-param"_hash:
                        protoparam = itemVal;
                        break;
                    case "obfs"_hash:
                    {
                        switch(hash_(itemVal))
                        {
                        case "http"_hash:
                        case "tls"_hash:
                            plugin = "simple-obfs";
                            pluginopts_mode = itemVal;
                            break;
                        case "wss"_hash:
                            tls = "tls";
                            [[fallthrough]];
                        case "ws"_hash:
                            pluginopts_mode = "websocket";
                            plugin = "v2ray-plugin";
                            break;
                        default:
                            pluginopts_mode = itemVal;
                        }
                        break;
                    }
                    case "obfs-host"_hash:
                        pluginopts_host = itemVal;
                        break;
                    case "obfs-uri"_hash:
                        path = itemVal;
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;
                switch(hash_(plugin))
                {
                case "simple-obfs"_hash:
                    pluginopts = "obfs=" + pluginopts_mode;
                    if(!pluginopts_host.empty())
                        pluginopts += ";obfs-host=" + pluginopts_host;
                    break;
                case "v2ray-plugin"_hash:
                    if(pluginopts_host.empty() && !isIPv4(server) && !isIPv6(server))
                        pluginopts_host = server;
                    pluginopts = "mode=" + pluginopts_mode;
                    if(!pluginopts_host.empty())
                        pluginopts += ";host=" + pluginopts_host;
                    if(!path.empty())
                        pluginopts += ";path=" + path;
                    pluginopts += ";" + tls;
                    break;
                }

                if(!protocol.empty())
                {
                    ssrConstruct(node, SSR_DEFAULT_GROUP, remarks, server, port, protocol, method, pluginopts_mode, password, pluginopts_host, protoparam, udp, tfo, scv);
                }
                else
                {
                    ssConstruct(node, SS_DEFAULT_GROUP, remarks, server, port, password, method, plugin, pluginopts, udp, tfo, scv, tls13);
                }
                break;
            case "vmess"_hash: //quantumult x style vmess link
                server = trim(configs[0].substr(0, configs[0].rfind(":")));
                port = trim(configs[0].substr(configs[0].rfind(":") + 1));
                if(port == "0")
                    continue;
                net = "tcp";

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitConfigPair(trim(configs[i]));
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "method"_hash:
                        method = itemVal;
                        break;
                    case "password"_hash:
                        id = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "obfs"_hash:
                        switch(hash_(itemVal))
                        {
                        case "ws"_hash:
                            net = "ws";
                            break;
                        case "over-tls"_hash:
                            tls = "tls";
                            break;
                        case "wss"_hash:
                            net = "ws";
                            tls = "tls";
                            break;
                        }
                        break;
                    case "obfs-host"_hash:
                        host = itemVal;
                        break;
                    case "obfs-uri"_hash:
                        path = itemVal;
                        break;
                    case "over-tls"_hash:
                        tls = itemVal == "true" ? "tls" : "";
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "aead"_hash:
                        aead = itemVal == "true" ? "0" : "1";
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                vmessConstruct(node, V2RAY_DEFAULT_GROUP, remarks, server, port, "", id, aead, net, method, path, host, "", tls, "", udp, tfo, scv, tls13);
                break;
            case "trojan"_hash: //quantumult x style trojan link
                server = trim(configs[0].substr(0, configs[0].rfind(':')));
                port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                if(port == "0")
                    continue;

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitConfigPair(trim(configs[i]));
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "password"_hash:
                        password = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "over-tls"_hash:
                        tls = itemVal;
                        break;
                    case "tls-host"_hash:
                        host = itemVal;
                        break;
                    case "udp-relay"_hash:
                        udp = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    case "tls-verification"_hash:
                        scv = itemVal == "false";
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                trojanConstruct(node, TROJAN_DEFAULT_GROUP, remarks, server, port, password, "", host, "", tls == "true", udp, tfo, scv, tls13);
                break;
            case "http"_hash: //quantumult x style http links
                server = trim(configs[0].substr(0, configs[0].rfind(':')));
                port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                if(port == "0")
                    continue;

                for(i = 1; i < configs.size(); i++)
                {
                    vArray = splitConfigPair(trim(configs[i]));
                    if(vArray.size() != 2)
                        continue;
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch(hash_(itemName))
                    {
                    case "username"_hash:
                        username = itemVal;
                        break;
                    case "password"_hash:
                        password = itemVal;
                        break;
                    case "tag"_hash:
                        remarks = itemVal;
                        break;
                    case "over-tls"_hash:
                        tls = itemVal;
                        break;
                    case "tls-verification"_hash:
                        scv = itemVal == "false";
                        break;
                    case "tls13"_hash:
                        tls13 = itemVal;
                        break;
                    case "fast-open"_hash:
                        tfo = itemVal;
                        break;
                    default:
                        continue;
                    }
                }
                if(remarks.empty())
                    remarks = server + ":" + port;

                if(username == "none")
                    username.clear();
                if(password == "none")
                    password.clear();

                httpConstruct(node, HTTP_DEFAULT_GROUP, remarks, server, port, username, password, tls == "true", tfo, scv, tls13);
                break;
            case "anytls"_hash: //quantumult x style anytls link
            {
                server = trim(configs[0].substr(0, configs[0].rfind(':')));
                port = trim(configs[0].substr(configs[0].rfind(':') + 1));
                uint32_t anytls_port = 0;
                if(!share_uri::number(port, anytls_port, 65535) || anytls_port == 0) continue;
                std::string certificate_pin;
                bool unsupported = false;

                for (i = 1; i < configs.size(); i++) {
                    vArray = splitConfigPair(trim(configs[i]));
                    if(vArray.size() != 2) { unsupported = true; continue; }
                    itemName = trim(vArray[0]);
                    itemVal = trim(vArray[1]);
                    switch (hash_(itemName)) {
                        case "password"_hash:
                            password = itemVal;
                            break;
                        case "tag"_hash:
                            remarks = itemVal;
                            break;
                        case "tls-host"_hash:
                        case "sni"_hash:
                            host = itemVal;
                            break;
                        case "udp-relay"_hash:
                            udp = itemVal;
                            break;
                        case "fast-open"_hash:
                            tfo = itemVal;
                            break;
                        case "tls-verification"_hash:
                            scv = itemVal == "false";
                            break;
                        case "tls13"_hash:
                            tls13 = itemVal;
                            break;
                        case "tls-cert-sha256"_hash:
                            certificate_pin = itemVal;
                            break;
                        case "over-tls"_hash:
                            if(itemVal != "true") unsupported = true;
                            break;
                        default:
                            unsupported = true;
                            break;
                    }
                }
                if(unsupported || (!certificate_pin.empty() && scv.get()))
                {
                    writeLog(0, "Skipped QX AnyTLS node: unsupported option or inactive certificate pin", LOG_LEVEL_WARNING);
                    continue;
                }
                anyTLSConstruct(node, ANYTLS_DEFAULT_GROUP, remarks, server, port, password, host, udp, tfo, scv, "");
                node.Fingerprint = certificate_pin;
                node.TLS13 = tls13;
                break;
            }
            default:
                continue;
            }
            break;
        }

        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
    return index;
}

void explodeSSTap(std::string sstap, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    std::string configType, group, remarks, server, port;
    std::string cipher;
    std::string user, pass;
    std::string protocol, protoparam, obfs, obfsparam;
    Document json;
    uint32_t index = nodes.size();
    json.Parse(sstap.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    for(uint32_t i = 0; i < json["configs"].Size(); i++)
    {
        Proxy node;
        auto source_record = registry->reserve(GetMember(json["configs"][i], "remarks"));
        json["configs"][i]["group"] >> group;
        json["configs"][i]["remarks"] >> remarks;
        json["configs"][i]["server"] >> server;
        port = GetMember(json["configs"][i], "server_port");
        if(port == "0")
            continue;

        if(remarks.empty())
            remarks = server + ":" + port;

        json["configs"][i]["password"] >> pass;
        json["configs"][i]["type"] >> configType;
        switch(to_int(configType, 0))
        {
        case 5: //socks 5
            json["configs"][i]["username"] >> user;
            socksConstruct(node, group, remarks, server, port, user, pass);
            break;
        case 6: //ss/ssr
            json["configs"][i]["protocol"] >> protocol;
            json["configs"][i]["obfs"] >> obfs;
            json["configs"][i]["method"] >> cipher;
            if(find(ss_ciphers.begin(), ss_ciphers.end(), cipher) != ss_ciphers.end() && protocol == "origin" && obfs == "plain") //is ss
            {
                ssConstruct(node, group, remarks, server, port, pass, cipher, "", "");
            }
            else //is ssr cipher
            {
                json["configs"][i]["obfsparam"] >> obfsparam;
                json["configs"][i]["protocolparam"] >> protoparam;
                ssrConstruct(node, group, remarks, server, port, protocol, cipher, obfs, pass, obfsparam, protoparam);
            }
            break;
        default:
            continue;
        }

        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

void explodeNetchConf(std::string netch, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    Document json;
    uint32_t index = nodes.size();

    json.Parse(netch.data());
    if(json.HasParseError() || !json.IsObject())
        return;

    if(!json.HasMember("Server"))
        return;

    for(uint32_t i = 0; i < json["Server"].Size(); i++)
    {
        Proxy node;
        auto source_record = registry->reserve(GetMember(json["Server"][i], "Remark"));
        explodeNetch("Netch://" + base64Encode(json["Server"][i] | SerializeObject()), node);

        if(node.Type == ProxyType::Unknown) continue;
        node.Id = index;
        attachSourceIdentity(node, registry, source_record);
        nodes.emplace_back(std::move(node));
        index++;
    }
}

int explodeConfContent(const std::string &input, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    const std::string without_bom = startsWith(input, "\xEF\xBB\xBF") ? input.substr(3) : std::string();
    const std::string &content = startsWith(input, "\xEF\xBB\xBF") ? without_bom : input;
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    const auto initial_size = nodes.size();
    ConfType filetype = ConfType::Unknow;
    const auto first = content.find_first_not_of(" \t\r\n");
    if(first != std::string::npos && (content[first] == '{' || content[first] == '['))
    {
        Document document;
        document.Parse(content.c_str());
        if(!document.HasParseError() && document.IsArray())
        {
            // Existing SS Android exports are arrays, not object containers.
            const bool android = std::any_of(document.Begin(), document.End(), [](const auto &item) { return item.IsObject() && item.HasMember("proxy_apps"); });
            if(android) filetype = ConfType::SSConf;
            else return 0;
        }
        else if(!document.HasParseError() && document.IsObject())
        {
            if((document.HasMember("proxies") && document["proxies"].IsArray()) ||
               (document.HasMember("Proxy") && document["Proxy"].IsArray()))
            {
                explodeClash(YAML::Load(content), nodes, registry);
                return !nodes.empty();
            }
            // Classify real JSON containers, never keywords in arbitrary URI data.
            if(document.HasMember("version")) filetype = ConfType::SS;
            else if(document.HasMember("serverSubscribes")) filetype = ConfType::SSR;
            else if(document.HasMember("uiItem") || document.HasMember("outbounds")) filetype = ConfType::V2Ray;
            else if(document.HasMember("idInUse")) filetype = ConfType::SSTap;
            else if(document.HasMember("local_address") && document.HasMember("local_port")) filetype = ConfType::SSR;
            else if(document.HasMember("ModeFileNameType")) filetype = ConfType::Netch;
            else return 0;
        }
    }

    switch(filetype)
    {
    case ConfType::SS:
        explodeSSConf(content, nodes, registry);
        break;
    case ConfType::SSR:
        explodeSSRConf(content, nodes, registry);
        break;
    case ConfType::V2Ray:
        explodeVmessConf(content, nodes, registry);
        break;
    case ConfType::SSConf:
        explodeSSAndroid(content, nodes, registry);
        break;
    case ConfType::SSTap:
        explodeSSTap(content, nodes, registry);
        break;
    case ConfType::Netch:
        explodeNetchConf(content, nodes, registry);
        break;
    default:
        //try to parse as a local subscription
        explodeSub(content, nodes, registry);
    }

    for(size_t i = initial_size; i < nodes.size(); ++i) attachSourceIdentity(nodes[i], registry);
    return !nodes.empty();
}

void explode(const std::string &link, Proxy &node, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    node.SourceRegistryRef = registry;
    node.SourceIdentity = share_uri::reserveSource(link, registry);
    if(startsWith(link, "ssr://"))
        explodeSSR(link, node, registry);
    else if(startsWith(link, "vmess://") || startsWith(link, "vmess1://"))
        explodeVmess(link, node, registry);
    else if(startsWith(link, "ss://"))
        explodeSS(link, node);
    else if(startsWith(link, "socks://") || startsWith(link, "https://t.me/socks") || startsWith(link, "tg://socks"))
        explodeSocks(link, node);
    else if(startsWith(link, "https://t.me/http") || startsWith(link, "tg://http")) //telegram style http link
        explodeHTTP(link, node);
    else if(startsWith(link, "Netch://"))
        explodeNetch(link, node, registry);
    else if(startsWith(link, "tuic://"))
        explodeTuic(link, node);
    else if(startsWith(link, "vless://"))
        explodeVless(link, node);
    else if(startsWith(link, "trojan://"))
        explodeTrojan(link, node);
    else if (startsWith(link, "hysteria2://") || startsWith(link, "hy2://"))
        explodeHysteria2(link, node);
    else if (startsWith(link, "anytls://"))
        explodeAnyTLS(link, node);
    else if(isLink(link))
        explodeHTTPSub(link, node);
    if(node.Type != ProxyType::Unknown) attachSourceIdentity(node, registry);
}

static bool isRawUriSubscription(const std::string &content)
{
    std::stringstream lines(content);
    std::string line;
    while(std::getline(lines, line))
    {
        line = trim(line);
        if(line.empty() || line.front() == '#') continue;
        return regFind(line, "^[A-Za-z][A-Za-z0-9+.-]*://");
    }
    return false;
}

void explodeSub(std::string sub, std::vector<Proxy> &nodes, SourceRegistry registry)
{
    if(!registry) registry = std::make_shared<SourceNodeRegistry>();
    std::stringstream strstream;
    std::string strLink;
    bool processed = false;
    const bool raw_uri = isRawUriSubscription(sub);

    //try to parse as SSD configuration
    if(startsWith(sub, "ssd://"))
    {
        explodeSSD(sub, nodes, registry);
        processed = true;
    }

    //try to parse as clash configuration
    try
    {
        if(!processed && !raw_uri && regFind(sub, "\"?(Proxy|proxies)\"?:"))
        {
            regGetMatch(sub, R"(^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)", 1, &sub);
            Node yamlnode = Load(sub);
            if(yamlnode.size() && (yamlnode["Proxy"].IsDefined() || yamlnode["proxies"].IsDefined()))
            {
                explodeClash(yamlnode, nodes, registry);
                processed = true;
            }
        }
    }
    catch (std::exception &e)
    {
        //writeLog(0, e.what(), LOG_LEVEL_DEBUG);
        //ignore
        throw;
    }

    //try to parse as surge configuration
    if(!processed && !raw_uri && explodeSurge(sub, nodes, registry))
    {
        processed = true;
    }

    //try to parse as normal subscription
    if(!processed)
    {
        // A mixed plaintext URI subscription must not be Base64-decoded again.
        // Unknown schemes remain visible to the unsupported-entry diagnostics.
        if(!raw_uri)
            sub = urlSafeBase64Decode(sub);
        if(!isRawUriSubscription(sub) && regFind(sub, "(vmess|shadowsocks|http|trojan)\\s*?="))
        {
            if(explodeSurge(sub, nodes, registry))
                return;
        }
        strstream << sub;
        char delimiter = count(sub.begin(), sub.end(), '\n') < 1 ? count(sub.begin(), sub.end(), '\r') < 1 ? ' ' : '\r' : '\n';
        while(getline(strstream, strLink, delimiter))
        {
            Proxy node;
            if(strLink.rfind('\r') != std::string::npos)
                strLink.erase(strLink.size() - 1);
            strLink = trim(strLink);
            if(strLink.empty() || strLink.front() == '#') continue;
            explode(strLink, node, registry);
            if(strLink.empty()) continue;
            if(node.Type == ProxyType::Unknown)
            {
                writeLog(0, "Skipped invalid or unsupported subscription entry (content redacted)", LOG_LEVEL_WARNING);
                continue;
            }
            nodes.emplace_back(std::move(node));
        }
    }
}
