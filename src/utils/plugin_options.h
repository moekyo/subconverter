#ifndef SUBCONVERTER_PLUGIN_OPTIONS_H
#define SUBCONVERTER_PLUGIN_OPTIONS_H
#include <map>
#include <string>

// SIP003 option separators are semicolons. Literal ';', '=' and '\\' in
// values are escaped. '&' inside a value is data, never a TLS/mux flag.
inline std::string escapePluginOption(const std::string &value)
{
    std::string out;
    for(char c:value){if(c==';'||c=='='||c=='\\')out+='\\';out+=c;}
    return out;
}
struct PluginOptions
{
    std::map<std::string,std::string> values;
    bool parse(const std::string &input)
    {
        values.clear();
        // Retain the narrow legacy mode-first '&' spelling. A standard
        // semicolon-delimited host/path containing '&' never takes this path.
        const char delimiter=input.find(';')==std::string::npos&&
            (input.rfind("mode=websocket&",0)==0||input.rfind("mode=quic&",0)==0)?'&':';';
        std::string key,value;bool in_value=false,escaped=false;
        auto finish=[&]()
        {
            if(key.empty())return value.empty()&&!in_value;
            auto [it,inserted]=values.emplace(key,value);
            const bool valid=inserted||it->second==value;
            key.clear();value.clear();in_value=false;return valid;
        };
        for(char c:input)
        {
            if(escaped)
            {if(c!=';'&&c!='='&&c!='\\')return false;(in_value?value:key)+=c;escaped=false;continue;}
            if(c=='\\'){escaped=true;continue;}
            if(c==delimiter){if(!finish())return false;continue;}
            if(c=='='&&!in_value){in_value=true;continue;}
            (in_value?value:key)+=c;
        }
        return !escaped&&finish();
    }
    std::string get(const std::string &key) const
    {const auto p=values.find(key);return p==values.end()?std::string():p->second;}
    bool tls() const {return values.count("tls")!=0;}
    bool mux(bool &enabled) const
    {
        const auto p=values.find("mux");
        enabled=false;if(p==values.end())return true;
        if(p->second.empty()){enabled=true;return true;}
        unsigned long long n=0;
        for(unsigned char c:p->second){if(c<'0'||c>'9'||n>2147483647ULL/10)return false;n=n*10+c-'0';if(n>2147483647)return false;}
        enabled=n!=0;return true;
    }
};
#endif
