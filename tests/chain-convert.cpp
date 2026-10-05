#include <algorithm>
#include <iostream>
#include <iterator>
#include "nlohmann/json.hpp"
#include "generator/config/subexport.h"
#include "generator/config/nodemanip.h"
#include "parser/subparser.h"

using json = nlohmann::json;

// Synthetic offline driver. Every parser, filter, preprocessor and exporter is
// linked from the production static library; no extracted preprocessing shim.
static json snapshot(const std::vector<Proxy> &nodes, const SourceRegistry &registry)
{
    json result = {{"nodes", json::array()}, {"records", json::array()}};
    for(const auto &node : nodes)
        result["nodes"].push_back({{"name", node.Remark}, {"dependency", node.UnderlyingProxy},
                                  {"plugin", node.Plugin}, {"plugin_options", node.PluginOption},
                                  {"source_name", node.SourceIdentity ? node.SourceIdentity->Name : ""}});
    for(const auto &record : registry->Records)
        result["records"].push_back({{"name", record->Name}, {"dependency", record->Dependency},
                                    {"state", static_cast<int>(record->Status)}});
    return result;
}

static std::string render(const std::string &target, const json &request,
                          std::vector<Proxy> &nodes, extra_settings &ext)
{
    ProxyGroupConfigs groups;
    for(const auto &item : request.at("groups"))
    {
        ProxyGroupConfig group;
        group.Name = item.at("name").get<std::string>();
        group.Type = ProxyGroupType::Select;
        group.Proxies = item.at("members").get<string_array>();
        groups.push_back(std::move(group));
    }
    std::vector<RulesetContent> rules;
    const auto bases = request.value("bases", json::object());
    if(target == "clash")
        return proxyToClash(nodes, bases.value("clash", std::string("mode: rule\nrules:\n  - MATCH,Exit\n")), rules, groups, false, ext);
    if(target == "surge")
        return proxyToSurge(nodes, bases.value("surge", std::string("[General]\nloglevel = notify\n[Proxy]\n[Proxy Group]\n[Rule]\nFINAL,Exit\n")), rules, groups, 4, ext);
    if(target == "singbox")
        return proxyToSingBox(nodes, bases.value("singbox", std::string("{\"route\":{\"final\":\"Exit\"}}")), rules, groups, ext);
    throw std::runtime_error("Unknown target");
}

int main(int argc, char **argv)
{
    if(argc != 2) return 64;
    try
    {
        const auto request = json::parse(std::string(std::istreambuf_iterator<char>(std::cin), {}));
        extra_settings ext;
        ext.enable_rule_generator = false;
        ext.clash_new_field_name = request.value("clash_new_field_name", true);
        ext.clash_proxies_style = "block";
        ext.clash_proxy_groups_style = "block";
        ext.nodelist = request.value("list", false);
        ext.append_proxy_type = request.value("append", false);
        ext.remove_emoji = request.value("remove_emoji", false);
        ext.add_emoji = request.value("add_emoji", false);
        ext.sort_flag = request.value("sort", false);
        for(const auto &rule : request.value("rename", json::array()))
            ext.rename_array.push_back({rule.at(0).get<std::string>(), rule.at(1).get<std::string>(), ""});
        for(const auto &rule : request.value("emoji", json::array()))
            ext.emoji_array.push_back({rule.at(0).get<std::string>(), rule.at(1).get<std::string>(), ""});

        std::vector<Proxy> nodes;
        json meta = {{"documents", json::array()}, {"pre_exports", json::array()}};
        for(const auto &document : request.at("documents"))
        {
            // Parse every input separately, as merged subscription intake does.
            // An all-rejected source still contributes records to shared registry.
            std::vector<Proxy> parsed;
            const auto content = document.is_string() ? document.get<std::string>() : document.dump();
            const int ok = explodeConfContent(content, parsed, ext.source_registry);
            meta["documents"].push_back({{"parsed", parsed.size()}, {"status", ok}});
            nodes.insert(nodes.end(), parsed.begin(), parsed.end());
        }
        meta["parsed"] = snapshot(nodes, ext.source_registry);
        auto exclude = request.value("exclude", string_array{});
        auto include = request.value("include", string_array{});
        if(!exclude.empty() || !include.empty()) filterNodes(nodes, exclude, include, 0);
        const auto erase_names = request.value("simulate_filter_erase", string_array{});
        // This intentionally simulates the erase boundary only. markSourceFiltered
        // is the same helper called by production JS filters; no JS engine is run.
        nodes.erase(std::remove_if(nodes.begin(), nodes.end(), [&](const Proxy &node) {
            if(std::find(erase_names.begin(), erase_names.end(), node.Remark) == erase_names.end()) return false;
            markSourceFiltered(node);
            return true;
        }), nodes.end());
        meta["filtered"] = snapshot(nodes, ext.source_registry);
        preprocessNodes(nodes, ext);
        const auto before = snapshot(nodes, ext.source_registry);
        meta["before_export"] = before;
        for(const auto &prior : request.value("pre_exports", json::array()))
        {
            const auto output = render(prior.get<std::string>(), request, nodes, ext);
            meta["pre_exports"].push_back({{"target", prior}, {"bytes", output.size()},
                                          {"failed", ext.chain_conversion_failed},
                                          {"mutated", snapshot(nodes, ext.source_registry) != before}});
        }
        const auto output = render(argv[1], request, nodes, ext);
        meta["failed"] = ext.chain_conversion_failed;
        meta["mutated"] = snapshot(nodes, ext.source_registry) != before;
        meta["after_export"] = snapshot(nodes, ext.source_registry);
        std::cerr << "CHAIN_META " << meta.dump() << '\n';
        std::cout.write(output.data(), output.size());
        return ext.chain_conversion_failed ? 3 : 0;
    }
    catch(const std::exception &)
    {
        std::cerr << "Invalid synthetic chain test request\n";
        return 2;
    }
}
