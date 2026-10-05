#include <iostream>
#include <iterator>
#include "parser/subparser.h"
#include "parser/conversion_report.h"
#include "generator/config/subexport.h"
int main(int argc,char **argv)
{
    if(argc!=2)return 1;
    const std::string input(std::istreambuf_iterator<char>(std::cin),{});
    auto registry=std::make_shared<SourceNodeRegistry>();
    registry->Report=std::make_shared<ConversionReport>("0123456789abcdef0123456789abcdef");
    registry->Report->beginSource("synthetic://source");registry->Report->sourceContent(input);
    std::vector<Proxy> nodes;std::string output;int status=200;
    try
    {
        if(!registry->Report->canParseSource()||!explodeConfContent(input,nodes,registry))status=400;
        extra_settings ext;ext.source_registry=registry;ext.clash_new_field_name=true;ext.enable_rule_generator=false;ext.nodelist=true;ext.clash_proxies_style="block";
        std::vector<RulesetContent> rules;
        const std::string target=argv[1];
        if(target=="clash")output=proxyToClash(nodes,"{}",rules,{},false,ext);
        else if(target=="surge")output=proxyToSurge(nodes,"[Proxy]\n",rules,{},4,ext);
        else if(target=="singbox")output=proxyToSingBox(nodes,"{}",rules,{},ext);
        if(ext.chain_conversion_failed)status=400;
    }
    catch(const std::exception &){status=400;}
    std::cout<<registry->Report->finish(argv[1],output,status);return status==200?0:2;
}
