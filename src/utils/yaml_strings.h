#ifndef SUBCONVERTER_YAML_STRINGS_H
#define SUBCONVERTER_YAML_STRINGS_H
#include <set>
#include <string>
#include <cstdlib>
#include <yaml-cpp/yaml.h>
#include "utils/regexp.h"

// The downstream guarded PyYAML loader retains these YAML 1.1 float forms,
// which yaml-cpp's numeric conversion does not recognize (notably '_' and ':').
inline bool yamlFloatLexical(const std::string &value)
{
    return regMatch(value,R"(^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$)");
}

// yaml-cpp scalar nodes do not retain the C++ constructor's scalar type.
// Tag only ambiguous values in fields that this exporter defines as strings.
inline bool ambiguousYamlString(const YAML::Node &node)
{
    const auto value=node.Scalar();bool boolean=false;double number=0;
    if(value.empty()||value=="null"||value=="Null"||value=="NULL"||value=="~")return true;
    if(YAML::convert<bool>::decode(node,boolean)||YAML::convert<double>::decode(node,number))return true;
    if(yamlFloatLexical(value))return true;
    if(value.size()>=10&&value[4]=='-'&&value[7]=='-')return true;
    if(std::string("+-0123456789.").find(value.front())!=std::string::npos)
    {if(value.find_first_of("_:")!=std::string::npos)return true;char *end=nullptr;std::strtod(value.c_str(),&end);if(end==value.c_str()+value.size())return true;}
    return false;
}
inline void preserveYamlStrings(YAML::Node node,bool text_context=false)
{
    static const std::set<std::string> strings={"name","type","server","username","password","uuid","cipher","plugin","sni","servername","client-fingerprint","fingerprint","public-key","private-key","pre-shared-key","token","auth-str","ca","ca-str","obfs-password","flow","packet-encoding","path","mode","protocol","protocol-param","protocolparam","obfs","obfs-param","obfsparam","short-id","grpc-service-name","dialer-proxy","ports"};
    if(node.IsScalar()) {if(text_context&&ambiguousYamlString(node))node.SetTag("tag:yaml.org,2002:str");return;}
    if(node.IsSequence()){for(auto entry:node)preserveYamlStrings(entry,text_context);return;}
    if(node.IsMap())for(auto entry:node)
    {
        const auto key=entry.first.Scalar();
        preserveYamlStrings(entry.second,text_context||strings.count(key)||key=="headers"||key=="alpn"||key=="host");
    }
}
#endif
