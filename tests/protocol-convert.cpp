#include <iostream>
#include <iterator>
#include "generator/config/subexport.h"
#include "parser/subparser.h"

// Offline harness: production parsers/exporters, synthetic input on stdin.
int main(int argc, char **argv)
{
    if(argc != 4) return 1;
    const std::string input(std::istreambuf_iterator<char>(std::cin), {});
    std::vector<Proxy> nodes;
    try {
        if(!explodeConfContent(input, nodes)) return 2;
        extra_settings ext;
        ext.enable_rule_generator = false;
        ext.clash_new_field_name = true;
        ext.clash_proxies_style = argv[2];
        ext.nodelist = std::string(argv[3]) == "list";
        std::vector<RulesetContent> rules;
        const std::string target = argv[1];
        if(target == "clash") std::cout << proxyToClash(nodes, "{}", rules, {}, false, ext);
        else if(target == "quanx") std::cout << proxyToQuanX(nodes, "[server_local]\n", rules, {}, ext);
        else if(target == "surge") std::cout << proxyToSurge(nodes, "[Proxy]\n", rules, {}, 4, ext);
        else if(target == "loon") std::cout << proxyToLoon(nodes, "[Proxy]\n", rules, {}, ext);
        else if(target == "quan") std::cout << proxyToQuan(nodes, "[SERVER]\n", rules, {}, ext);
        else if(target == "mellow") std::cout << proxyToMellow(nodes, "[Endpoint]\n", rules, {}, ext);
        else if(target == "singbox") std::cout << proxyToSingBox(nodes, "{}", rules, {}, ext);
        else if(target == "mixed") std::cout << proxyToSingle(nodes, 15, ext);
        else if(target == "ss-uri") std::cout << proxyToSingle(nodes, 1, ext);
        else if(target == "ssr-uri") std::cout << proxyToSingle(nodes, 2, ext);
        else return 1;
        if(ext.chain_conversion_failed) return 3;
    } catch(const std::exception &) {
        // Do not print input, credentials, or exception strings containing them.
        std::cerr << "Invalid synthetic subscription input\n";
        return 2;
    }
}
