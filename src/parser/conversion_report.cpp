#include "conversion_report.h"
#include "conversion_uri.h"
#include "config/proxy.h"
#include "utils/base64/base64.h"
#include "utils/sha256.h"
#include "utils/string.h"
#include "utils/yaml_strings.h"
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <set>
#include <sstream>

namespace
{
using Writer = rapidjson::Writer<rapidjson::StringBuffer>;
const std::set<std::string> nodeKeys = {
    "name","type","server","port","username","password","uuid","alterId","cipher","tls","udp","tfo","fast-open",
    "skip-cert-verify","tls13","sni","servername","client-fingerprint","fingerprint","alpn","ca","ca-str",
    "network","flow","packet-encoding","dialer-proxy","underlying-proxy","ws-opts","ws-path","ws-headers",
    "grpc-opts","h2-opts","http-opts","reality-opts","plugin","plugin-opts","protocol","protocol-param","protocolparam",
    "obfs","obfs-param","obfsparam","obfs-opts","version","private-key","public-key","pre-shared-key","ip","ipv6",
    "dns","mtu","reserved","keepalive","allowed-ips","ports","up","down","up-speed","down-speed","auth","auth-str",
    "obfs-protocol","obfs-password","recv-window-conn","recv-window","disable-mtu-discovery","hop-interval","cwnd",
    "idle-session-check-interval","idle-session-timeout","min-idle-session","token","congestion-controller","udp-relay-mode",
    "reduce-rtt","disable-sni","request-timeout","max-udp-relay-packet-size","fast-open","heartbeat-interval",
    "udp-over-stream","udp-over-stream-version"};
const std::set<std::string> protocols = {"ss","ssr","vmess","trojan","vless","anytls","tuic","hysteria","hysteria2","http","socks5","snell","wireguard"};
const std::set<std::string> booleanKeys={"tls","udp","tfo","fast-open","skip-cert-verify","tls13","disable-mtu-discovery","reduce-rtt","disable-sni","udp-over-stream"};
const std::set<std::string> integerKeys={"port","alterId","version","mtu","keepalive","up","down","up-speed","down-speed","recv-window-conn","recv-window","hop-interval","cwnd","idle-session-check-interval","idle-session-timeout","min-idle-session","request-timeout","max-udp-relay-packet-size","heartbeat-interval","udp-over-stream-version"};
const std::set<std::string> mapKeys={"ws-opts","ws-headers","grpc-opts","h2-opts","http-opts","reality-opts","plugin-opts","obfs-opts"};
const std::set<std::string> listKeys={"alpn","dns","reserved"};
void text(Writer &w, const char *key, const std::string &value) { w.Key(key); w.String(value.data(), value.size()); }
void number(Writer &w,const char *key,size_t n) {w.Key(key);w.Uint64(n);}
std::string kind(const YAML::Node &n)
{
    if(!n.IsDefined()) return "absent";
    if(n.IsNull()) return "null";
    if(n.IsMap()) return "object";
    if(n.IsSequence()) return "array";
    const auto tag=n.Tag(), s=n.Scalar();
    if(tag=="!"||tag=="tag:yaml.org,2002:str"||tag=="str") return "string";
    // Explicit types take precedence over an implicitly decodable spelling.
    // In particular, !!float +443 must not become an integer equivalence.
    if(tag=="tag:yaml.org,2002:bool") return "boolean";
    if(tag=="tag:yaml.org,2002:int") return "integer";
    if(tag=="tag:yaml.org,2002:float") return "number";
    if(!tag.empty()&&tag!="?") return "unknown-tag";
    bool boolean=false;int64_t integer=0;uint64_t unsigned_integer=0;double number=0;
    if(YAML::convert<bool>::decode(n,boolean)) return "boolean";
    if(YAML::convert<int64_t>::decode(n,integer)||YAML::convert<uint64_t>::decode(n,unsigned_integer)) return "integer";
    if(YAML::convert<double>::decode(n,number)||yamlFloatLexical(s)) return "number";
    if(!s.empty()&&std::string("+-0123456789.").find(s.front())!=std::string::npos)
    {char *end=nullptr;std::strtod(s.c_str(),&end);if(end==s.c_str()+s.size()&&end!=s.c_str())return "number";}
    if(s.size()>=10&&s[4]=='-'&&s[7]=='-'&&(s.size()==10||s[10]=='T'||s[10]=='t'||s[10]==' '))return "timestamp";
    return "string";
}
bool sameScalar(const YAML::Node &a,const YAML::Node &b)
{
    if(!a.IsScalar()||!b.IsScalar())return false;
    const auto type=kind(a);
    if(type!=kind(b))return false;
    if(type=="boolean")
    {
        // yaml-cpp also accepts YAML 1.1 y/yes/on spellings. Do not expand
        // completeness to those forms: the guarded consumer uses core bools.
        const auto core_bool=[](const std::string &s)
        {return s=="true"||s=="True"||s=="TRUE"||s=="false"||s=="False"||s=="FALSE";};
        if(!core_bool(a.Scalar())||!core_bool(b.Scalar()))return false;
        bool left=false,right=false;
        return YAML::convert<bool>::decode(a,left)&&YAML::convert<bool>::decode(b,right)&&left==right;
    }
    if(type=="integer")
    {
        const auto decimal=[](const std::string &s)
        {
            const size_t first=!s.empty()&&(s.front()=='+'||s.front()=='-')?1:0;
            return first<s.size()&&(s[first]!='0'||first+1==s.size())&&
                std::all_of(s.begin()+first,s.end(),[](unsigned char c){return c>='0'&&c<='9';});
        };
        if(!decimal(a.Scalar())||!decimal(b.Scalar()))return false;
        int64_t left=0,right=0;
        if(YAML::convert<int64_t>::decode(a,left)&&YAML::convert<int64_t>::decode(b,right))return left==right;
        // Do not reinterpret a negative value as an unsigned integer or use
        // floating point, which would lose precision above 2^53.
        if(a.Scalar().find('-')!=std::string::npos||b.Scalar().find('-')!=std::string::npos)return false;
        uint64_t unsigned_left=0,unsigned_right=0;
        return YAML::convert<uint64_t>::decode(a,unsigned_left)&&YAML::convert<uint64_t>::decode(b,unsigned_right)&&unsigned_left==unsigned_right;
    }
    // Credentials, strings and explicit REALITY representation maps retain
    // their literal spelling. Other scalar types receive no normalization.
    return a.Scalar()==b.Scalar();
}
bool stringList(const YAML::Node &value)
{
    if(!value.IsSequence())return false;
    for(const auto &item:value)if(kind(item)!="string")return false;
    return true;
}
bool headers(const YAML::Node &value,bool lists)
{
    if(!value.IsMap())return false;
    for(const auto &item:value)if(kind(item.first)!="string"||(lists?!stringList(item.second):kind(item.second)!="string"))return false;
    return true;
}
bool optionTypes(const std::string &option,const YAML::Node &value)
{
    if(!value.IsMap())return false;
    if(option=="ws-headers")return headers(value,false);
    const std::map<std::string,std::map<std::string,std::string>> schemas={
        {"ws-opts",{{"path","string"},{"headers","headers"},{"max-early-data","integer"},{"early-data-header-name","string"},{"v2ray-http-upgrade","boolean"},{"v2ray-http-upgrade-fast-open","boolean"}}},
        {"grpc-opts",{{"grpc-service-name","string"}}},
        {"h2-opts",{{"path","string"},{"host","strings"}}},
        {"http-opts",{{"method","string"},{"path","strings"},{"headers","header-lists"}}},
        {"reality-opts",{{"public-key","string"},{"short-id","string"},{"support-x25519mlkem768","boolean"}}},
        {"plugin-opts",{{"mode","string"},{"host","string"},{"path","string"},{"tls","boolean"},{"mux","boolean"},{"skip-cert-verify","boolean"}}},
        {"obfs-opts",{{"mode","string"},{"host","string"}}}};
    const auto schema=schemas.find(option);if(schema==schemas.end())return false;
    for(const auto &entry:value)
    {
        if(!entry.first.IsScalar())return false;
        const auto type=schema->second.find(entry.first.Scalar());if(type==schema->second.end())return false;
        if(option=="reality-opts"&&entry.first.Scalar()=="short-id"&&kind(entry.second)=="integer")
        {
            const auto digits=entry.second.Scalar();
            if(digits.size()<=16&&digits.size()%2==0&&std::all_of(digits.begin(),digits.end(),[](unsigned char c){return c>='0'&&c<='9';}))continue;
        }
        if(type->second=="strings") {if(!stringList(entry.second))return false;}
        else if(type->second=="headers") {if(!headers(entry.second,false))return false;}
        else if(type->second=="header-lists") {if(!headers(entry.second,true))return false;}
        else if(kind(entry.second)!=type->second)return false;
    }
    return true;
}
bool validNodeTypes(const YAML::Node &input)
{
    if(!input.IsMap())return false;
    for(const auto &entry:input)
    {
        if(!entry.first.IsScalar())return false;
        const auto key=entry.first.Scalar();const auto &value=entry.second;
        if(!nodeKeys.count(key))continue;
        const auto type=kind(value);
        if(booleanKeys.count(key)) {if(type!="boolean")return false;}
        else if(integerKeys.count(key)) {if(type!="integer")return false;}
        else if(mapKeys.count(key)) {if(type!="object"||!optionTypes(key,value))return false;}
        else if(listKeys.count(key))
        {
            if(type!="array")return false;
            for(const auto &item:value)if(kind(item)!=(key=="reserved"?"integer":"string"))return false;
        }
        else if(type!="string")return false;
    }
    return true;
}
bool bounded(const YAML::Node &node,size_t &fields,size_t depth,std::vector<YAML::Node> &parents,std::string &reason)
{
    if(++fields>ConversionReport::max_fields||depth>32) {reason="LIMIT_EXCEEDED";return false;}
    static const std::set<std::string> tags={"","?","!","str","tag:yaml.org,2002:str","tag:yaml.org,2002:bool","tag:yaml.org,2002:int","tag:yaml.org,2002:float","tag:yaml.org,2002:null","tag:yaml.org,2002:map","tag:yaml.org,2002:seq"};
    if(!tags.count(node.Tag())) {reason="MALFORMED_INPUT";return false;}
    for(const auto &parent:parents) if(parent.is(node)) {reason="MALFORMED_INPUT";return false;}
    parents.push_back(node);
    std::set<std::string> keys;
    if(node.IsMap()) for(const auto &item:node)
    {
        if(!item.first.IsScalar()||kind(item.first)!="string"||!tags.count(item.first.Tag())) {reason="MALFORMED_INPUT";return false;}
        if(!keys.insert(item.first.Scalar()).second) {reason="DUPLICATE_FIELD";return false;}
        if(!bounded(item.second,fields,depth+1,parents,reason)) return false;
    }
    else if(node.IsSequence()) for(const auto &item:node) if(!bounded(item,fields,depth+1,parents,reason)) return false;
    parents.pop_back(); return true;
}
YAML::Node lookup(const YAML::Node &n,const std::string &key)
{
    if(n.IsMap()) for(const auto &item:n) if(item.first.IsScalar()&&item.first.Scalar()==key) return item.second;
    return YAML::Node(YAML::NodeType::Undefined);
}
std::string alias(const std::string &key,const YAML::Node &output)
{
    if(key=="fast-open") return "tfo";
    if(key=="underlying-proxy") return "dialer-proxy";
    if(key=="protocolparam"&&lookup(output,"protocol-param").IsDefined()) return "protocol-param";
    if(key=="protocol-param"&&lookup(output,"protocolparam").IsDefined()) return "protocolparam";
    if(key=="obfsparam"&&lookup(output,"obfs-param").IsDefined()) return "obfs-param";
    if(key=="obfs-param"&&lookup(output,"obfsparam").IsDefined()) return "obfsparam";
    if(key=="servername"&&!lookup(output,"servername").IsDefined()&&lookup(output,"sni").IsDefined()) return "sni";
    if(key=="sni"&&!lookup(output,"sni").IsDefined()&&lookup(output,"servername").IsDefined()) return "servername";
    return key;
}
struct Field {std::vector<size_t> path;std::string disposition,reason;};
struct NodeResult {const ConversionInputNode *input;std::vector<Field> fields,output_fields;std::string reason,status;size_t output=0;bool emitted=false;};
void compareFields(const YAML::Node &input,const YAML::Node &output,std::vector<size_t> path,std::vector<Field> &fields,
                   const std::string &forced="",const std::string &mapped="",bool root=false)
{
    std::string reason=forced,disposition="PRESERVED";
    if(reason.empty())
    {
        if(!output.IsDefined()) reason="FIELD_DROPPED";
        else if(kind(input)!=kind(output)) reason="FIELD_TYPE_CHANGED";
        else if(input.IsScalar()&&!sameScalar(input,output)) reason="FIELD_CHANGED";
        else if(input.IsSequence()&&input.size()!=output.size()) reason="FIELD_CHANGED";
    }
    if(!reason.empty()) disposition=reason=="FORMAT_UNVERIFIED"||reason=="TARGET_UNVERIFIED"?"UNVERIFIED":"REJECTED";
    else if(!mapped.empty()) {disposition="MAPPED";reason=mapped;}
    else reason="EXACT";
    fields.push_back({path,disposition,reason});
    if(input.IsMap())
    {
        size_t i=0;
        for(const auto &item:input)
        {
            const auto key=item.first.IsScalar()?item.first.Scalar():"";
            auto child=path;child.push_back(i++);
            auto key2=root?alias(key,output):key;
            std::string nested=forced;
            if(root&&!nodeKeys.count(key)) nested="UNKNOWN_FIELD";
            const auto target=lookup(output,key2);
            compareFields(item.second,target,child,fields,nested,key!=key2?"ALIAS_MAPPED":"");
        }
    }
    else if(input.IsSequence()) for(size_t i=0;i<input.size();++i)
    {
        auto child=path;child.push_back(i);
        const auto target=output.IsSequence()&&i<output.size()?output[i]:YAML::Node(YAML::NodeType::Undefined);
        compareFields(input[i],target,child,fields,forced);
    }
}
void inventoryFields(const YAML::Node &input,std::vector<size_t> path,std::vector<Field> &fields,const std::string &disposition,const std::string &reason)
{
    fields.push_back({path,disposition,reason});
    if(input.IsMap())
    {
        size_t i=0;for(const auto &entry:input){auto child=path;child.push_back(i++);inventoryFields(entry.second,child,fields,disposition,reason);}
    }
    else if(input.IsSequence())for(size_t i=0;i<input.size();++i){auto child=path;child.push_back(i);inventoryFields(input[i],child,fields,disposition,reason);}
}
YAML::Node projectedInput(const YAML::Node &input,const YAML::Node &output,bool root=true)
{
    if(input.IsMap())
    {
        YAML::Node projected(YAML::NodeType::Map);
        for(const auto &entry:input)
        {
            const auto key=root?alias(entry.first.Scalar(),output):entry.first.Scalar();
            projected[key]=projectedInput(entry.second,lookup(output,key),false);
        }
        return projected;
    }
    if(input.IsSequence())
    {
        YAML::Node projected(YAML::NodeType::Sequence);
        for(size_t i=0;i<input.size();++i)projected.push_back(projectedInput(input[i],output.IsSequence()&&i<output.size()?output[i]:YAML::Node(YAML::NodeType::Undefined),false));
        return projected;
    }
    return YAML::Clone(input);
}
bool defaultValue(const std::string &protocol,const std::string &plugin,const std::vector<std::string> &path,const YAML::Node &actual)
{
    if(path.size()==1)
    {
        const auto &key=path[0];
        if((protocol=="vmess"||protocol=="vless"||protocol=="http")&&key=="tls"&&sameScalar(actual,YAML::Node(false)))return true;
        if(protocol=="vmess"&&key=="alterId"&&sameScalar(actual,YAML::Node(0)))return true;
        if(protocol=="vmess"&&key=="cipher"&&kind(actual)=="string"&&actual.Scalar()=="auto")return true;
        if(protocol=="vless"&&key=="network"&&kind(actual)=="string"&&actual.Scalar()=="tcp")return true;
        if(protocol=="ssr"&&(key=="protocol-param"||key=="protocolparam"||key=="obfs-param"||key=="obfsparam")&&kind(actual)=="string"&&actual.Scalar().empty())return true;
    }
    if(protocol=="ss"&&plugin=="v2ray-plugin"&&path.size()==2&&path[0]=="plugin-opts")
    {
        if(path[1]=="tls"&&sameScalar(actual,YAML::Node(false)))return true;
        if(path[1]=="mux"&&sameScalar(actual,YAML::Node(true)))return true;
        if(path[1]=="host"&&kind(actual)=="string"&&actual.Scalar()=="bing.com")return true;
        if(path[1]=="path"&&kind(actual)=="string"&&actual.Scalar().empty())return true;
    }
    return false;
}
void outputFields(const YAML::Node &actual,const YAML::Node &expected,std::vector<size_t> ordinal,std::vector<std::string> path,
                  const std::string &protocol,const std::string &plugin,const std::map<std::string,YAML::Node> &configured,std::vector<Field> &fields)
{
    std::string disposition="PRESERVED",reason="EXACT";
    if(!expected.IsDefined())
    {
        bool configured_default=false;
        if(path.size()==1&&configured.count(path[0]))
        {
            const auto &value=configured.at(path[0]);
            configured_default=kind(value)==kind(actual)&&sameScalar(value,actual);
        }
        if(configured_default){disposition="MAPPED";reason="CONFIG_DEFAULT";}
        else if(defaultValue(protocol,plugin,path,actual)){disposition="MAPPED";reason="GENERATED_DEFAULT";}
        else {disposition="REJECTED";reason="OUTPUT_FIELD_UNEXPECTED";}
    }
    else if(kind(actual)!=kind(expected)) {disposition="REJECTED";reason="FIELD_TYPE_CHANGED";}
    else if((actual.IsScalar()&&!sameScalar(actual,expected))||(actual.IsSequence()&&actual.size()!=expected.size()))
    {disposition="REJECTED";reason="FIELD_CHANGED";}
    fields.push_back({ordinal,disposition,reason});
    if(actual.IsMap())
    {
        size_t index=0;
        for(const auto &entry:actual)
        {
            auto next_ordinal=ordinal;next_ordinal.push_back(index++);auto next_path=path;next_path.push_back(entry.first.Scalar());
            outputFields(entry.second,lookup(expected,entry.first.Scalar()),next_ordinal,next_path,protocol,plugin,configured,fields);
        }
    }
    else if(actual.IsSequence())for(size_t i=0;i<actual.size();++i)
    {
        auto next_ordinal=ordinal;next_ordinal.push_back(i);auto next_path=path;next_path.push_back(std::to_string(i));
        outputFields(actual[i],expected.IsSequence()&&i<expected.size()?expected[i]:YAML::Node(YAML::NodeType::Undefined),next_ordinal,next_path,protocol,plugin,configured,fields);
    }
}
}
ConversionReport::ConversionReport(std::string request_nonce)
{
    if(request_nonce.size()==32&&std::all_of(request_nonce.begin(),request_nonce.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))nonce=std::move(request_nonce);
}
bool ConversionReport::canParseSource() const
{
    return request_failure.empty()&&!sources.empty()&&sources[current].reason=="EXACT";
}
void ConversionReport::beginSource(const std::string &locator)
{
    if(sources.size()>=max_sources){request_failure="LIMIT_EXCEEDED";return;}
    current=sources.size();sources.emplace_back();
    sources.back().locator_sha256=sha256(nonce+std::string(1,'\0')+trimWhitespace(locator,true,true));
    sources.back().content_sha256=sha256("");
    sources.back().fetch_context_sha256=sha256("inline:"+locator);
}
void ConversionReport::sourceContent(const std::string &content)
{
    if(sources.empty()) beginSource("");
    auto &source=sources[current];source.content_sha256=sha256(content);
    if(content.empty()) return;
    if(content.size()>max_bytes-input_bytes) {source.reason="LIMIT_EXCEEDED";return;}
    input_bytes+=content.size();
    std::string decoded=content;
    for(unsigned encoding=0;encoding<8;++encoding)
    {
        YAML::Node root;
        try
        {
            const auto documents=YAML::LoadAll(decoded);
            if(documents.size()>1)
            {
                source.format="legacy-structured";source.reason="MALFORMED_INPUT";
                std::vector<YAML::Node> parents;
                for(const auto &document:documents)
                {
                    std::string reason;
                    if(!bounded(document,inventory_fields,0,parents,reason)) {source.reason=reason;source.nodes.clear();return;}
                    source.nodes.push_back({YAML::Clone(document)});
                }
                return;
            }
            if(!documents.empty()) root.reset(documents.front());
        }
        catch(const YAML::Exception &) {}
        if(root.IsMap()||root.IsSequence())
        {
            source.root.reset(root);
            std::vector<YAML::Node> parents;std::string reason;
            if(!bounded(root,inventory_fields,0,parents,reason)) {source.reason=reason;return;}
            const auto proxies=root.IsMap()?(root["proxies"].IsDefined()?root["proxies"]:root["Proxy"]):YAML::Node(YAML::NodeType::Undefined);
            if(proxies.IsSequence())
            {
                source.format=encoding?"base64-clash":"clash";source.reason="EXACT";
                if(proxies.size()>max_nodes) {source.reason="LIMIT_EXCEEDED";return;}
                for(const auto &node:proxies) source.nodes.push_back({YAML::Clone(node),nullptr,"COMPLETE","","EXACT"});
                for(const auto &entry:root) if(entry.first.Scalar()!="proxies"&&entry.first.Scalar()!="Proxy") source.reason="SOURCE_CONFIGURATION_UNHANDLED";
                if(root["proxies"].IsDefined()&&root["Proxy"].IsDefined()) source.reason="IDENTITY_AMBIGUOUS";
                return;
            }
            // Legacy structured containers remain inventoried, but do not get a
            // fidelity claim from the converter's own accepted-node list.
            source.format="legacy-structured";source.reason="FORMAT_UNVERIFIED";
            if(root.IsSequence()) for(const auto &node:root) source.nodes.push_back({YAML::Clone(node)});
            else
            {
                for(const char *key:{"servers","configs","vmess","Server","outbounds"})
                {
                    const auto entries=lookup(root,key);
                    if(entries.IsSequence()) for(const auto &node:entries)source.nodes.push_back({YAML::Clone(node)});
                    else if(entries.IsMap()) for(const auto &node:entries)source.nodes.push_back({YAML::Clone(node.second)});
                }
                if(source.nodes.empty())source.nodes.push_back({YAML::Clone(root)});
            }
            return;
        }
        const auto trimmed=trimWhitespace(decoded,true,true);
        if(trimmed.find("://")!=std::string::npos||(!trimmed.empty()&&trimmed[0]=='[')||trimmed.find(" = ")!=std::string::npos)
        {
            source.format=encoding?"base64-uri":"uri";source.reason="EXACT";
            std::stringstream lines(decoded);std::string line;
            const char delimiter=decoded.find('\n')!=std::string::npos?'\n':decoded.find('\r')!=std::string::npos?'\r':' ';
            while(std::getline(lines,line,delimiter))
            {
                line=trimWhitespace(line,true,true);
                if(line.empty()||line.front()=='#'||line.front()==';'||line.compare(0,2,"//")==0) continue;
                ConversionInputNode node;node.uri_token=line;
                if(line.size()>65536){source.reason="LIMIT_EXCEEDED";return;}
                if(inventoryShareUri(line,node.input,node.original,node.reason)) node.coverage="COMPLETE";
                else {node.input=YAML::Node(line);source.reason=node.reason;}
                std::vector<YAML::Node> parents;std::string limit_reason;
                if(!bounded(node.input,inventory_fields,0,parents,limit_reason)||!bounded(node.original,inventory_fields,0,parents,limit_reason))
                {source.reason=limit_reason;source.nodes.clear();return;}
                source.nodes.push_back(std::move(node));
                if(source.nodes.size()>max_nodes) {source.reason="LIMIT_EXCEEDED";return;}
            }
            return;
        }
        auto next=urlSafeBase64Decode(decoded);
        if(next.empty()||next.size()>=decoded.size()) break;
        decoded=std::move(next);
    }
    source.reason="FORMAT_UNVERIFIED";source.nodes.push_back({YAML::Node(content)});
}
void ConversionReport::bindClashNode(size_t index,const std::shared_ptr<SourceNodeIdentity> &identity)
{
    if(sources.empty()||index>=sources[current].nodes.size()) {request_failure="IDENTITY_AMBIGUOUS";return;}
    auto &node=sources[current].nodes[index];
    if(node.identity) {request_failure="IDENTITY_AMBIGUOUS";return;}
    node.identity=identity.get();
}
void ConversionReport::emitted(const SourceNodeIdentity *identity,const std::string &name)
{
    if(identity&&!emitted_names.emplace(identity,name).second) request_failure="IDENTITY_AMBIGUOUS";
}
void ConversionReport::bindUriNode(const std::string &token,const std::shared_ptr<SourceNodeIdentity> &identity)
{
    if(sources.empty()) {request_failure="IDENTITY_AMBIGUOUS";return;}
    for(auto &node:sources[current].nodes) if(!node.identity&&node.uri_token==token)
    {node.identity=identity.get();return;}
    request_failure="IDENTITY_AMBIGUOUS";
}
std::string ConversionReport::finish(const std::string &target,const std::string &output,int &status)
{
    const int upstream_status=status;
    std::string failure=request_failure;
    if(status>=400) failure="CONVERSION_FAILED";
    YAML::Node output_nodes;
    const bool target_supported=target=="clash"||target=="clashr";
    if(!target_supported) failure="TARGET_UNVERIFIED";
    if(output.size()>max_bytes) failure="LIMIT_EXCEEDED";
    if(target_supported&&status<400&&output.size()<=max_bytes)
    {
        try
        {
            const auto documents=YAML::LoadAll(output);
            if(documents.size()!=1||!documents[0].IsMap())throw YAML::RepresentationException(YAML::Mark::null_mark(),"invalid output document");
            const auto document=documents[0];
            if(document["proxies"].IsDefined()&&document["Proxy"].IsDefined())throw YAML::RepresentationException(YAML::Mark::null_mark(),"ambiguous output node collection");
            output_nodes.reset(document["proxies"].IsDefined()?document["proxies"]:document["Proxy"]);
            size_t fields=0;std::vector<YAML::Node> parents;std::string reason;
            if(!output_nodes.IsSequence()||!bounded(output_nodes,fields,0,parents,reason))
            {failure=reason.empty()?"OUTPUT_INVALID":reason;output_nodes.reset(YAML::Node(YAML::NodeType::Undefined));}
        }
        catch(const YAML::Exception &) {failure="OUTPUT_INVALID";}
    }
    std::map<std::string,std::vector<size_t>> indexes;
    if(output_nodes.IsSequence()) for(size_t i=0;i<output_nodes.size();++i)
        if(lookup(output_nodes[i],"name").IsScalar()) indexes[output_nodes[i]["name"].Scalar()].push_back(i);
    std::vector<std::vector<NodeResult>> results(sources.size());
    std::set<size_t> used;bool pass=failure.empty()&&!sources.empty()&&output_nodes.IsSequence()&&output_nodes.size()>0;
    for(size_t s=0;s<sources.size();++s)
    {
        const auto &source=sources[s];
        pass=pass&&source.reason=="EXACT"&&!source.nodes.empty()&&source.provenance!="stale-cache"&&source.provenance!="unavailable";
        for(const auto &input:source.nodes)
        {
            NodeResult result{&input,{}, {},"EXACT","PASS"};
            YAML::Node actual(YAML::NodeType::Undefined);
            if(!target_supported) result.reason="TARGET_UNVERIFIED";
            else if(input.coverage!="COMPLETE") result.reason=input.reason;
            else if(!validNodeTypes(input.input)) result.reason="MALFORMED_INPUT";
            else if(lookup(input.input,"type").IsScalar()&&!protocols.count(input.input["type"].Scalar())) result.reason="PROTOCOL_UNSUPPORTED";
            else if(!input.identity&&source.reason!="EXACT") result.reason=source.reason;
            else if(!input.identity||input.identity->Status==SourceNodeIdentity::State::Rejected) result.reason="NODE_REJECTED";
            else if(input.identity->Status==SourceNodeIdentity::State::Filtered) result.reason="NODE_FILTERED";
            else
            {
                const auto emitted=emitted_names.find(input.identity);
                if(emitted==emitted_names.end()) result.reason="NODE_OMITTED";
                else
                {
                    const auto found=indexes.find(emitted->second);
                    if(found==indexes.end()) result.reason="NODE_OMITTED";
                    else if(found->second.size()!=1||!used.insert(found->second[0]).second) result.reason="IDENTITY_AMBIGUOUS";
                    else {result.emitted=true;result.output=found->second[0];actual.reset(output_nodes[result.output]);}
                }
            }
            auto expected=YAML::Clone(input.input);
            std::map<std::vector<size_t>,std::string> mapped_fields;
            if(result.emitted&&expected.IsMap())
            {
                size_t index=0;
                for(const auto &field:input.input)
                {
                    const auto key=field.first.Scalar();
                    if(key=="name"&&field.second.IsScalar()&&field.second.Scalar()!=emitted_names.at(input.identity))
                    {expected[key]=emitted_names.at(input.identity);expected[key].SetTag("tag:yaml.org,2002:str");mapped_fields[{index}]="NAME_TRANSFORMED";}
                    if((key=="dialer-proxy"||key=="underlying-proxy")&&field.second.IsScalar())
                    {
                        std::vector<std::string> matches;
                        for(const auto &origin:sources) for(const auto &candidate:origin.nodes)
                            if(candidate.identity&&candidate.identity->Name==field.second.Scalar()&&emitted_names.count(candidate.identity))matches.push_back(emitted_names.at(candidate.identity));
                        if(matches.size()==1&&matches[0]!=field.second.Scalar()) {expected[key]=matches[0];expected[key].SetTag("tag:yaml.org,2002:str");mapped_fields[{index}]="DEPENDENCY_RENAMED";}
                    }
                    if(key=="reality-opts"&&field.second.IsMap())
                    {
                        size_t subindex=0;
                        for(const auto &option:field.second)
                        {
                            if(option.first.Scalar()=="short-id"&&kind(option.second)=="integer")
                            {expected[key]["short-id"]=option.second.Scalar();expected[key]["short-id"].SetTag("tag:yaml.org,2002:str");mapped_fields[{index,subindex}]="REPRESENTATION_MAPPED";}
                            ++subindex;
                        }
                    }
                    ++index;
                }
            }
            compareFields(expected,actual,{},result.fields,result.reason=="EXACT"?"":result.reason,"",true);
            for(auto &field:result.fields) if(field.disposition=="PRESERVED")
            {
                if(mapped_fields.count(field.path)) {field.disposition="MAPPED";field.reason=mapped_fields.at(field.path);}
                else if(!input.uri_token.empty()) {field.disposition="MAPPED";field.reason="REPRESENTATION_MAPPED";}
            }
            for(const auto &field:result.fields) if(field.disposition=="REJECTED"||field.disposition=="UNVERIFIED")
            {result.reason=field.reason;result.status=field.disposition=="UNVERIFIED"?"UNVERIFIED":"FAIL";break;}
            if(result.emitted)
            {
                const auto type=lookup(expected,"type");
                const auto plugin=lookup(expected,"plugin");
                outputFields(actual,projectedInput(expected,actual),{},{},type.IsScalar()?type.Scalar():"",plugin.IsScalar()?plugin.Scalar():"",configured_defaults,result.output_fields);
                for(const auto &field:result.output_fields)if(field.disposition=="REJECTED") {result.reason=field.reason;result.status="FAIL";break;}
            }
            if(!input.uri_token.empty())
            {
                // The URI inventory retains all original components and every
                // query occurrence. Semantic expansion above is a separate,
                // explicit mapping check, never the source field inventory.
                result.fields.clear();
                inventoryFields(input.original.IsDefined()?input.original:input.input,{},result.fields,
                    result.status=="PASS"?"MAPPED":"REJECTED",result.status=="PASS"?"REPRESENTATION_MAPPED":result.reason);
            }
            pass=pass&&result.status=="PASS";
            results[s].push_back(std::move(result));
        }
    }
    pass=pass&&used.size()==output_nodes.size();
    if(!pass) status=422;
    rapidjson::StringBuffer buffer;Writer w(buffer);
    static const std::set<std::string> public_targets={"auto","clash","clashr","surge","surfboard","quan","quanx","loon","mellow","singbox","ss","ssd","ssr","sssub","v2ray","trojan","mixed"};
    w.StartObject();text(w,"schema","subconverter.completeness/v1");text(w,"nonce",nonce);text(w,"target",public_targets.count(target)?target:"unknown");
    w.Key("upstream_status");w.Int(upstream_status);
    text(w,"output",pass?output:"");text(w,"output_sha256",sha256(pass?output:""));
    w.Key("report");w.StartObject();text(w,"status",pass?"PASS":"FAIL");text(w,"reason",pass?"EXACT":failure.empty()?"CONVERSION_FAILED":failure);
    w.Key("sources");w.StartArray();
    for(size_t s=0;s<sources.size();++s)
    {
        const auto &source=sources[s];w.StartObject();number(w,"ordinal",s);
        text(w,"locator_sha256",source.locator_sha256);text(w,"content_sha256",source.content_sha256);
        text(w,"fetch_context_sha256",source.fetch_context_sha256);text(w,"provenance",source.provenance);
        text(w,"format",source.format);text(w,"coverage",source.reason=="EXACT"&&source.provenance!="stale-cache"?"COMPLETE":"UNVERIFIED");text(w,"reason",source.provenance=="stale-cache"?"STALE_SOURCE":source.reason);
        w.Key("input_nodes");w.StartArray();
        for(size_t n=0;n<results[s].size();++n)
        {
            const auto &result=results[s][n];w.StartObject();number(w,"ordinal",n);text(w,"status",result.status);text(w,"reason",result.reason);
            w.Key("output_ordinal");if(result.emitted) w.Uint64(result.output);else w.Null();
            w.Key("fields");w.StartArray();
            for(const auto &field:result.fields)
            {
                w.StartObject();w.Key("path");w.StartArray();for(auto index:field.path) w.Uint64(index);w.EndArray();
                text(w,"disposition",field.disposition);text(w,"reason",field.reason);w.EndObject();
            }
            w.EndArray();
            w.Key("output_fields");w.StartArray();
            for(const auto &field:result.output_fields)
            {
                w.StartObject();w.Key("path");w.StartArray();for(auto index:field.path)w.Uint64(index);w.EndArray();
                text(w,"disposition",field.disposition);text(w,"reason",field.reason);w.EndObject();
            }
            w.EndArray();w.EndObject();
        }
        w.EndArray();w.EndObject();
    }
    w.EndArray();w.EndObject();w.EndObject();return buffer.GetString();
}
