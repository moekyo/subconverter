#include <iostream>
#include <iterator>
#include <stdexcept>
#include <map>
#include <set>
#include <future>
#include "generator/config/subexport.h"
#include "handler/settings.h"
#include "parser/subparser.h"

static void require(bool value, const char *message)
{
    if(!value) throw std::runtime_error(message);
}

int main()
{
    try {
        const std::string input(std::istreambuf_iterator<char>(std::cin), {});
        std::vector<Proxy> fixture, nodes;
        require(explodeConfContent(input, fixture), "fixture parse");
        require(fixture.size() == 13, "complete protocol fixture");
        for(size_t i = 0; i < 146; ++i)
        {
            Proxy p = fixture[i % fixture.size()];
            p.Remark = "Node-" + getProxyTypeName(p.Type) + "-" + std::to_string(i);
            nodes.push_back(p);
        }
        auto base = YAML::Load(R"(
proxy-groups:
  - {name: DNP, type: select, proxies: [REJECT]}
  - {name: AI Suite, type: select, proxies: [REJECT, Safe fallback]}
  - {name: US-STRICT, type: select, proxies: [REJECT]}
  - {name: SameName, type: select, proxies: [DIRECT]}
)");
        ProxyGroupConfig health;
        health.Name = "Safe fallback";
        health.Type = ProxyGroupType::Fallback;
        health.Proxies = {"[]REJECT", "!!TYPE=(ANYTLS|TUIC)"};
        health.Url = "https://example.com/health";
        health.Interval = 600; health.Timeout = 3000; health.Tolerance = 50;
        health.Lazy = false; health.MaxFailedTimes = 4;
        health.ExpectedStatus = "204"; health.EvaluateBeforeUse = true;
        ProxyGroupConfig replace;
        replace.Name = "SameName"; replace.Type = ProxyGroupType::Select; replace.Proxies = {"[]REJECT"};
        ProxyGroupConfig empty;
        empty.Name = "AI empty"; empty.Type = ProxyGroupType::Select; empty.Proxies = {"[]REJECT", "^never-matches$"};
        extra_settings ext;
        ext.enable_rule_generator = false; ext.clash_new_field_name = true;
        proxyToClash(nodes, base, {health, replace, empty}, false, ext);
        require(base["proxies"].size() == 146, "complete 146-node conversion");
        for(size_t i = 0; i < nodes.size(); ++i)
            require(base["proxies"][i]["name"].as<std::string>() == nodes[i].Remark, "node order");
        auto groups = base["proxy-groups"];
        require(groups.size() == 6, "base groups preserved, same-name replaced");
        const char *names[] = {"DNP", "AI Suite", "US-STRICT", "SameName", "Safe fallback", "AI empty"};
        std::map<std::string, YAML::Node> graph;
        for(size_t i = 0; i < groups.size(); ++i)
        {
            require(groups[i]["name"].as<std::string>() == names[i], "group order");
            graph[names[i]] = groups[i];
        }
        auto check = graph["Safe fallback"];
        require(check["lazy"].as<bool>() == false, "fallback lazy false");
        require(check["timeout"].as<int>() == 3000, "fallback timeout");
        require(check["tolerance"].as<int>() == 50, "fallback tolerance");
        require(check["max-failed-times"].as<int>() == 4, "fallback max failures");
        require(check["expected-status"].as<std::string>() == "204", "fallback expected status");
        require(check["evaluate-before-use"].as<bool>(), "fallback eager evaluation");
        require(check["proxies"].size() > 1, "AnyTLS and TUIC type matchers");
        for(const char *root : {"AI Suite", "US-STRICT", "AI empty"})
        {
            std::vector<std::string> stack = {root};
            std::set<std::string> seen;
            while(!stack.empty())
            {
                auto name = stack.back(); stack.pop_back();
                require(name != "DIRECT", "no DIRECT reachable from guarded groups");
                if(!seen.insert(name).second || !graph.count(name)) continue;
                for(const auto &member : graph[name]["proxies"]) stack.push_back(member.as<std::string>());
            }
        }
        require(graph["AI empty"]["proxies"].size() == 1 && graph["AI empty"]["proxies"][0].as<std::string>() == "REJECT", "empty guarded group is REJECT");
        std::string rules, duplicates;
        for(int i = 0; i < 44426; ++i) rules += "DOMAIN,rule-" + std::to_string(i) + ".example\n";
        duplicates = "DOMAIN,rule-0.example\nDOMAIN,rule-44425.example\n";
        auto make = [](const char *group, const std::string &text) {
            RulesetContent source;
            source.rule_group = group;
            std::promise<std::string> promise; promise.set_value(text);
            source.rule_content = promise.get_future().share();
            return source;
        };
        std::vector<RulesetContent> sources = {make("AI Suite", rules), make("DIRECT", duplicates)};
        global.maxAllowedRules = 0; // Synthetic scale check, not a production settings change.
        rulesetToClash(base, sources, true, true);
        require(base["rules"].size() == 44426, "first-match dedup rule count");
        for(int i = 0; i < 44426; ++i)
            require(base["rules"][i].as<std::string>() == "DOMAIN,rule-" + std::to_string(i) + ".example,AI Suite", "rule value, target and order");
        std::cout << "PASS: 146 nodes, 44426 rules, base/DNP groups, health fields, AnyTLS/TUIC matchers, first-match order, guarded no-DIRECT and empty REJECT\n";
    } catch(const std::exception &e) {
        std::cerr << "Policy contract failed: " << e.what() << '\n'; return 1;
    }
}
