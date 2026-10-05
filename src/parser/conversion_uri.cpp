#include "conversion_uri.h"
#include "share_uri.h"
#include "utils/base64/base64.h"
#include "utils/urlencode.h"
#include "utils/string.h"
#include <set>

namespace
{
void str(YAML::Node node,const std::string &key,const std::string &value)
{node[key]=value;node[key].SetTag("tag:yaml.org,2002:str");}
}
bool inventoryShareUri(const std::string &original,YAML::Node &fields,YAML::Node &original_fields,std::string &reason)
{
    fields.reset(YAML::Node(YAML::NodeType::Map));
    original_fields.reset(YAML::Node(YAML::NodeType::Map));
    reason="FORMAT_UNVERIFIED";
    const auto separator=original.find("://");
    if(separator==std::string::npos) {reason="MALFORMED_INPUT";return false;}
    const auto scheme=original.substr(0,separator);
    str(original_fields,"scheme",scheme);
    const auto fragment=original.find('#',separator+3);
    const auto question=original.find('?',separator+3);
    const auto endpoint_end=std::min(fragment,question);
    str(original_fields,"authority",original.substr(separator+3,endpoint_end==std::string::npos?endpoint_end:endpoint_end-separator-3));
    if(fragment!=std::string::npos) str(original_fields,"fragment",original.substr(fragment+1));
    if(question!=std::string::npos&&(fragment==std::string::npos||question<fragment))
    {
        const auto query=original.substr(question+1,fragment==std::string::npos?fragment:fragment-question-1);
        original_fields["query"]=YAML::Node(YAML::NodeType::Sequence);
        for(size_t start=0;start<query.size();)
        {
            auto end=query.find('&',start);if(end==std::string::npos)end=query.size();
            const auto pair=query.substr(start,end-start);
            const auto equal=pair.find('=');
            YAML::Node entry(YAML::NodeType::Map);str(entry,"key",pair.substr(0,equal));
            str(entry,"value",equal==std::string::npos?"":pair.substr(equal+1));
            original_fields["query"].push_back(entry);start=end+1;
        }
    }
    if(scheme=="vmess")
    {
        YAML::Node raw;
        try {raw=YAML::Load(urlSafeBase64Decode(original.substr(separator+3)));}catch(const YAML::Exception &){reason="MALFORMED_INPUT";return false;}
        if(!raw.IsMap()){reason="MALFORMED_INPUT";return false;}
        const std::set<std::string> allowed={"v","ps","add","port","id","aid","net","type","host","path","tls","sni"};
        std::set<std::string> seen;
        for(const auto &entry:raw)
        {
            if(!entry.first.IsScalar()||!entry.second.IsScalar()){reason="MALFORMED_INPUT";return false;}
            if(!allowed.count(entry.first.Scalar())){reason="UNKNOWN_FIELD";return false;}
            if(!seen.insert(entry.first.Scalar()).second){reason="DUPLICATE_FIELD";return false;}
        }
        original_fields["document"]=YAML::Clone(raw); // All children proved scalar above.
        auto get=[&](const char *key){return raw[key].IsScalar()?raw[key].Scalar():std::string();};
        const auto version=get("v"),security=get("tls"),fake=get("type");
        if((!version.empty()&&version!="1"&&version!="2")||(!security.empty()&&security!="tls")||(!fake.empty()&&fake!="none")){reason="FIELD_UNSUPPORTED";return false;}
        uint32_t port=0,aid=0;
        if(!share_uri::number(get("port"),port,65535)||port==0||get("add").empty()||get("id").empty()||(!get("aid").empty()&&!share_uri::number(get("aid"),aid,65535))){reason="MALFORMED_INPUT";return false;}
        str(fields,"name",get("ps").empty()?get("add")+":"+get("port"):get("ps"));str(fields,"type","vmess");
        str(fields,"server",get("add"));fields["port"]=port;str(fields,"uuid",get("id"));fields["alterId"]=aid;
        str(fields,"cipher","auto");fields["tls"]=security=="tls";
        if(!get("sni").empty())str(fields,"servername",get("sni"));
        auto network=get("net");if(network.empty())network="tcp";
        auto path=get("path"),host=get("host");
        if(version!="2")
        {
            if(!path.empty()){reason="FIELD_UNSUPPORTED";return false;}
            const auto separator=host.find(';');
            if(separator!=std::string::npos){path=host.substr(separator+1);host.erase(separator);}
        }
        if(network=="tcp")
        {if(!path.empty()||!host.empty()){reason="FIELD_UNSUPPORTED";return false;}}
        else if(network=="ws")
        {
            str(fields,"network","ws");str(fields["ws-opts"],"path",path.empty()?"/":path);
            if(!host.empty())str(fields["ws-opts"]["headers"],"Host",host);
        }
        else {reason="FIELD_UNSUPPORTED";return false;}
        reason="EXACT";return true;
    }
    if(scheme!="ss"&&scheme!="anytls"&&scheme!="hysteria2"&&scheme!="hy2"&&scheme!="vless"&&scheme!="tuic"&&scheme!="trojan") return false;
    std::string uri=original;
    if(scheme=="ss")
    {
        const auto end=uri.find_first_of("?#");
        const auto authority=uri.substr(5,end==std::string::npos?end:end-5);
        if(authority.find('@')==std::string::npos)
        {
            const auto decoded=urlSafeBase64Decode(authority);const auto at=decoded.rfind('@');
            if(at==std::string::npos) {reason="MALFORMED_INPUT";return false;}
            uri="ss://"+urlEncode(decoded.substr(0,at))+"@"+decoded.substr(at+1)+(end==std::string::npos?"":uri.substr(end));
        }
    }
    const bool hy=scheme=="hysteria2"||scheme=="hy2";
    share_uri::Link link;
    if(!share_uri::parse(uri,scheme,link,hy||scheme=="anytls"?"443":"",hy,hy)) {reason="MALFORMED_INPUT";return false;}
    str(fields,"name",link.remark);str(fields,"type",hy?"hysteria2":scheme);str(fields,"server",link.server);
    uint32_t port=0;if(!share_uri::number(link.port,port,65535))return false;fields["port"]=port;
    if(scheme=="vless") str(fields,"uuid",link.userinfo);
    else if(scheme=="ss")
    {
        auto user=link.userinfo;
        if(user.find(':')==std::string::npos)user=urlSafeBase64Decode(user);
        const auto colon=user.find(':');if(colon==std::string::npos){reason="MALFORMED_INPUT";return false;}
        str(fields,"cipher",user.substr(0,colon));str(fields,"password",user.substr(colon+1));
    }
    else if(scheme=="tuic")
    {
        const auto colon=link.raw_userinfo.find(':');
        if(colon==std::string::npos)str(fields,"token",link.userinfo);
        else
        {
            std::string uuid,password;
            if(!share_uri::decode(link.raw_userinfo.substr(0,colon),uuid)||!share_uri::decode(link.raw_userinfo.substr(colon+1),password)){reason="MALFORMED_INPUT";return false;}
            str(fields,"uuid",uuid);str(fields,"password",password);
        }
    }
    else str(fields,"password",link.userinfo.empty()?link.get("password"):link.userinfo);
    if(hy&&!link.ports.empty())str(fields,"ports",link.ports);
    std::map<std::string,std::string> mapped;
    for(const auto &[key,value]:link.query)
    {
        std::string dest=key;
        if(key=="peer")dest="sni";
        else if(key=="fp")dest="client-fingerprint";
        else if(key=="pinSHA256")dest="fingerprint";
        else if(key=="insecure"||key=="allowInsecure"||key=="allow_insecure")dest="skip-cert-verify";
        else if(key=="congestion_control")dest="congestion-controller";
        else if(key=="udp_relay_mode")dest="udp-relay-mode";
        else if(key=="disable_sni")dest="disable-sni";
        else if(key=="reduce_rtt")dest="reduce-rtt";
        else if(key=="underlying-proxy")dest="dialer-proxy";
        auto [it,inserted]=mapped.emplace(dest,value);
        if(!inserted&&it->second!=value){reason="IDENTITY_AMBIGUOUS";return false;}
        // A declared URI group affects group selection rather than node fields;
        // no node-only equivalence claim is made for that directive.
        if(key=="group"||key=="plugin") {reason="FIELD_UNSUPPORTED";return false;}
        if(scheme=="vless"&&(key=="type"||key=="security"||key=="encryption"||key=="headerType"||key=="mode"||key=="host"||key=="path"||key=="serviceName"||key=="pbk"||key=="sid"))continue;
        const std::set<std::string> common={"sni","udp","tfo","skip-cert-verify","client-fingerprint","fingerprint","alpn"};
        const std::set<std::string> hyKeys={"obfs","obfs-password","up","down","ports","hop-interval","password"};
        const std::set<std::string> tuicKeys={"congestion-controller","udp-relay-mode","disable-sni","reduce-rtt","request-timeout","max-udp-relay-packet-size","heartbeat-interval","udp-over-stream","udp-over-stream-version","dialer-proxy"};
        const bool valid=common.count(dest)||(hy&&hyKeys.count(dest))||(scheme=="vless"&&(dest=="flow"||dest=="packet-encoding"))||(scheme=="tuic"&&tuicKeys.count(dest));
        if(!valid){reason="UNKNOWN_FIELD";return false;}
        if(dest=="alpn")
        {
            fields[dest]=split(value,",");
            for(auto item:fields[dest])item.SetTag("tag:yaml.org,2002:str");
        }
        else if(dest=="udp"||dest=="tfo"||dest=="skip-cert-verify"||dest=="disable-sni"||dest=="reduce-rtt"||dest=="udp-over-stream")
        {
            if(value!="true"&&value!="false"&&value!="1"&&value!="0"){reason="MALFORMED_INPUT";return false;}
            fields[dest]=value=="true"||value=="1";
        }
        else if(dest=="up"||dest=="down"||dest=="hop-interval"||dest=="request-timeout"||dest=="max-udp-relay-packet-size"||dest=="heartbeat-interval"||dest=="udp-over-stream-version")
        {
            uint32_t n=0;if(!share_uri::number(value,n)){reason="FIELD_UNSUPPORTED";return false;}fields[dest]=n;
        }
        else str(fields,dest,value);
    }
    if(scheme=="vless")
    {
        const auto encryption=link.get("encryption"),security=link.get("security"),header=link.get("headerType");
        if((!encryption.empty()&&encryption!="none")||(!header.empty()&&header!="none")||(!security.empty()&&security!="none"&&security!="tls"&&security!="reality")){reason="FIELD_UNSUPPORTED";return false;}
        const bool tls=security=="tls"||security=="reality";fields["tls"]=tls;
        auto network=link.get("type");if(network.empty())network="tcp";if(network=="http")network="h2";
        if(network!="tcp"&&network!="ws"&&network!="grpc"&&network!="h2"){reason="FIELD_UNSUPPORTED";return false;}
        str(fields,"network",network);
        if(tls)
        {
            str(fields,"servername",link.get("sni").empty()?link.server:link.get("sni"));fields.remove("sni");
            if(link.get("fp").empty())str(fields,"client-fingerprint","chrome");
        }
        if(security=="reality") {str(fields["reality-opts"],"public-key",link.get("pbk"));str(fields["reality-opts"],"short-id",link.get("sid"));}
        else if(!link.get("pbk").empty()||!link.get("sid").empty()){reason="FIELD_UNSUPPORTED";return false;}
        if(!link.get("mode").empty()&&!(network=="grpc"&&link.get("mode")=="gun")){reason="FIELD_UNSUPPORTED";return false;}
        const auto host=link.get("host"),path=link.get("path"),service=link.get("serviceName");
        if(network=="tcp"&&(!host.empty()||!path.empty()||!service.empty())){reason="FIELD_UNSUPPORTED";return false;}
        if(network=="ws")
        {if(!path.empty())str(fields["ws-opts"],"path",path);if(!host.empty())str(fields["ws-opts"]["headers"],"Host",host);if(!service.empty()){reason="FIELD_UNSUPPORTED";return false;}}
        if(network=="grpc")
        {if(!service.empty())str(fields["grpc-opts"],"grpc-service-name",service);if(!host.empty()||!path.empty()){reason="FIELD_UNSUPPORTED";return false;}}
        if(network=="h2")
        {if(!path.empty())str(fields["h2-opts"],"path",path);if(!host.empty()){fields["h2-opts"]["host"]=std::vector<std::string>{host};fields["h2-opts"]["host"][0].SetTag("tag:yaml.org,2002:str");}}
    }
    // For other schemes any protocol-specific unsupported query still makes the
    // production parser reject the identity; it cannot pass through this ledger.
    reason="EXACT";return true;
}
