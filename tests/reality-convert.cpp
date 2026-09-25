#include <iostream>
#include <iterator>

#include "generator/config/subexport.h"
#include "parser/subparser.h"

int main(int argc, char **argv)
{
    if(argc != 3)
        return 1;
    const std::string input(std::istreambuf_iterator<char>(std::cin), {});
    std::vector<Proxy> nodes;
    if(!explodeConfContent(input, nodes))
        return 1;
    extra_settings ext;
    ext.enable_rule_generator = false;
    ext.clash_new_field_name = true;
    ext.clash_proxies_style = argv[1];
    ext.nodelist = std::string(argv[2]) == "list";
    std::vector<RulesetContent> rules;
    std::cout << proxyToClash(nodes, "{}", rules, {}, false, ext);
}
