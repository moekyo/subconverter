#include "utils/plugin_options.h"
#include <iostream>
int main()
{
    int checks=0;auto require=[&](bool value){++checks;if(!value){std::cerr<<"plugin contract failure "<<checks<<'\n';std::exit(1);}};
    for(const auto &path:{"/mux","/x?foo=1&tls","/a;tls","/a\\b","/a=b"})
    {
        PluginOptions options;bool mux=true;
        require(options.parse("mode=websocket;host=tls.example;path="+escapePluginOption(path)+";"));
        require(options.get("path")==path&&!options.tls()&&options.mux(mux)&&!mux);
    }
    for(const auto &text:{"tls","tls;tls","tls=false","tls=0","tls=true"})
    {PluginOptions options;require(options.parse(text)&&options.tls());}
    for(const auto &text:{"mux=0","mux=0;mux=0","mode=websocket"})
    {PluginOptions options;bool mux=true;require(options.parse(text)&&options.mux(mux)&&!mux);}
    for(const auto &text:{"mux","mux=1","mux=8"})
    {PluginOptions options;bool mux=false;require(options.parse(text)&&options.mux(mux)&&mux);}
    for(const auto &text:{"tls=true;tls=false","mux=0;mux=1","path=x\\","host=x\\y"})
    {PluginOptions options;require(!options.parse(text));}
    for(const auto &text:{"mux=false","mux=-1","mux=2147483648"})
    {PluginOptions options;bool mux=false;require(options.parse(text)&&!options.mux(mux));}
    {PluginOptions options;bool mux=false;require(options.parse("mode=websocket&tls&host=front.invalid&path=/")&&options.tls()&&options.get("path")=="/");}
    std::cout<<checks<<" plugin option checks passed\n";
}
