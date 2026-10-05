#ifndef CLASH_GROUP_GRAPH_H
#define CLASH_GROUP_GRAPH_H

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <jpcre2.hpp>
#include <yaml-cpp/yaml.h>

// A local validation model only: the original base-group YAML is preserved.
// Dynamic provider contents and regexp2 extensions are not guessed here.
namespace clash_group_graph {
using Strings = std::vector<std::string>;
struct Group {
    Strings members, explicit_members;
    bool valid = true, opaque = false;
};
inline bool ascii(const std::string &s) {
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return c < 128; });
}
inline std::string lower(std::string s) {
    for(char &c : s) if(c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return s;
}
inline Strings split(const std::string &s, char delimiter) {
    Strings values;
    size_t start = 0, end;
    do { end = s.find(delimiter, start); values.push_back(s.substr(start, end - start)); start = end + 1; } while(end != std::string::npos);
    return values;
}
inline bool scalar(const YAML::Node &node, const char *key, std::string &out) {
    const auto value = node[key];
    if(!value.IsDefined() || value.IsNull()) { out.clear(); return true; }
    if(!value.IsScalar()) return false;
    out = value.as<std::string>();
    return true;
}
inline bool flag(const YAML::Node &node, const char *key, bool &out) {
    std::string value;
    if(!scalar(node, key, value)) return false;
    out = false;
    if(value.empty() || value == "0" || value == "f" || value == "F" || value == "false" || value == "False" || value == "FALSE") return true;
    if(value == "1" || value == "t" || value == "T" || value == "true" || value == "True" || value == "TRUE") { out = true; return true; }
    return false;
}
inline bool sequence(const YAML::Node &node, const char *key, Strings &out) {
    const auto value = node[key];
    if(!value.IsDefined() || value.IsNull()) return true;
    if(!value.IsSequence()) return false;
    for(const auto &item : value) {
        if(!item.IsScalar()) return false;
        out.push_back(item.as<std::string>());
    }
    return true;
}

// The tested regexp2 / PCRE2 intersection: literals, classes, anchors,
// quantifiers, alternation, ordinary/noncapturing groups and lookahead.
// Shorthand/Unicode classes, backreferences, lookbehind and engine-specific
// constructs remain unknown, rather than being interpreted differently.
inline bool regexSubset(const std::string &pattern, bool &fold) {
    fold = false;
    bool in_class = false;
    for(size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if(c == '\\') {
            if(++i == pattern.size()) return false;
            if(std::string("\\.^$|?*+()[]{}-/nrt").find(pattern[i]) == std::string::npos) return false;
            continue;
        }
        if(c == '[') { if(in_class) return false; in_class = true; continue; }
        if(c == ']') { if(!in_class) return false; in_class = false; continue; }
        if(in_class) continue;
        if(c == '{') {
            size_t end = i + 1, digits = end;
            while(end < pattern.size() && pattern[end] >= '0' && pattern[end] <= '9') ++end;
            if(end == digits) return false;
            if(end < pattern.size() && pattern[end] == ',') {
                ++end;
                while(end < pattern.size() && pattern[end] >= '0' && pattern[end] <= '9') ++end;
            }
            if(end == pattern.size() || pattern[end] != '}' || (end + 1 < pattern.size() && pattern[end + 1] == '+')) return false;
            i = end;
            continue;
        }
        if(c == '}') return false;
        if(c == '(' && i + 1 < pattern.size() && pattern[i + 1] == '*') return false;
        if(c == '(' && i + 1 < pattern.size() && pattern[i + 1] == '?') {
            if(pattern.compare(i, 4, "(?i)") == 0) { fold = true; i += 3; }
            else if(i + 2 < pattern.size() && (pattern[i + 2] == ':' || pattern[i + 2] == '=' || pattern[i + 2] == '!')) i += 2;
            else return false;
        }
        if((c == '*' || c == '+' || c == '?' || c == '}') && i + 1 < pattern.size() && pattern[i + 1] == '+') return false;
    }
    return !in_class && (!fold || ascii(pattern));
}
class Filter {
    using JP = jpcre2::select<char>;
    struct Part { std::string pattern; bool fold; };
    std::vector<Part> parts;
public:
    bool valid = true;
    explicit Filter(const std::string &patterns) {
        if(patterns.empty()) return;
        for(const auto &pattern : split(patterns, '`')) {
            bool fold = false;
            JP::Regex regex;
            if(!regexSubset(pattern, fold)) { valid = false; return; }
            regex.setPattern(pattern).setNewLine(PCRE2_NEWLINE_LF).addPcre2Option(PCRE2_UTF | PCRE2_ALT_BSUX).compile();
            if(!regex) { valid = false; return; }
            parts.push_back({pattern, fold});
        }
    }
    // Empty filter selects everything. For exclude-filter callers skip it.
    bool matches(const std::string &name, bool &matched) const {
        if(!valid) return false;
        matched = parts.empty();
        for(const auto &part : parts) {
            if(part.fold && !ascii(name)) return false;
            JP::Regex regex;
            regex.setPattern(part.pattern).setNewLine(PCRE2_NEWLINE_LF).addPcre2Option(PCRE2_UTF | PCRE2_ALT_BSUX).compile();
            if(!regex) return false;
            JP::RegexMatch match(&regex);
            const bool found = match.setSubject(name).match() != 0;
            const int error = match.getErrorNumber();
            if(error != 0 && error != PCRE2_ERROR_NOMATCH) return false;
            matched = matched || found;
        }
        return true;
    }
};
inline std::string adapterType(const std::string &type) {
    if(type == "ss") return "shadowsocks";
    if(type == "ssr") return "shadowsocksr";
    if(type == "select") return "selector";
    if(type == "url-test") return "urltest";
    if(type == "load-balance") return "loadbalance";
    return lower(type);
}

inline std::map<std::string, Group> build(const YAML::Node &proxies,
    const std::map<std::string, YAML::Node> &groups, const std::set<std::string> &providers,
    const std::set<std::string> &generated_empty) {
    std::map<std::string, std::string> nodes, types;
    for(const auto &proxy : proxies)
        nodes[proxy["name"].as<std::string>()] = adapterType(proxy["type"].as<std::string>());
    types = nodes;
    const std::map<std::string, std::string> builtins = {{"DIRECT", "direct"}, {"REJECT", "reject"},
        {"REJECT-DROP", "rejectdrop"}, {"COMPATIBLE", "compatible"}, {"PASS", "pass"}, {"PASS-RULE", "passrule"}};
    types.insert(builtins.begin(), builtins.end());
    for(const auto &[name, node] : groups) {
        std::string type;
        if(scalar(node, "type", type)) types[name] = adapterType(type);
    }
    std::map<std::string, Group> result;
    for(const auto &[name, node] : groups) {
        auto &group = result[name];
        bool all = false, all_proxies = false, all_providers = false;
        std::string filter, exclude, exclude_type, type, fallback;
        Strings use;
        if(!sequence(node, "proxies", group.explicit_members) || !sequence(node, "use", use) ||
           !flag(node, "include-all", all) || !flag(node, "include-all-proxies", all_proxies) ||
           !flag(node, "include-all-providers", all_providers) || !scalar(node, "filter", filter) ||
           !scalar(node, "exclude-filter", exclude) || !scalar(node, "exclude-type", exclude_type) ||
           !scalar(node, "type", type) || !scalar(node, "empty-fallback", fallback)) { group.valid = false; continue; }
        if(!ascii(exclude_type)) group.valid = false;
        if(type != "select" && type != "url-test" && type != "fallback" && type != "load-balance" && type != "relay") group.valid = false;
        group.members = group.explicit_members;
        if(all || all_providers) use.assign(providers.begin(), providers.end());
        for(const auto &provider : use) {
            if(!providers.count(provider)) group.valid = false;
            else group.opaque = true;
        }
        if(group.explicit_members.empty() && use.empty() && !all && !all_proxies) group.valid = false;
        Filter include_filter(filter), exclude_filter(exclude);
        if(!include_filter.valid || !exclude_filter.valid) { group.valid = false; continue; }
        if(all || all_proxies) for(const auto &[proxy, proxy_type] : nodes) {
            bool matched = false;
            if(!include_filter.matches(proxy, matched)) group.valid = false;
            else if(matched) group.members.push_back(proxy);
        }
        const bool had_members = !group.members.empty();
        if(providers.count(name) && (had_members || ((all || all_proxies) && use.empty()))) group.valid = false;
        Strings kept;
        const auto excluded_types = split(lower(exclude_type), '|');
        for(const auto &member : group.members) {
            bool excluded = false;
            if(!exclude.empty() && !exclude_filter.matches(member, excluded)) group.valid = false;
            const auto member_type = types.find(member);
            if(!exclude_type.empty() && member_type != types.end() && std::find(excluded_types.begin(), excluded_types.end(), member_type->second) != excluded_types.end()) excluded = true;
            if(!excluded && std::find(kept.begin(), kept.end(), member) == kept.end()) kept.push_back(member);
        }
        group.members = std::move(kept);
        // Only an explicitly chosen fallback can restore an empty local group.
        // Mihomo's implicit COMPATIBLE fallback must not hide a lost chain.
        if(!fallback.empty() && (!types.count(fallback) || groups.count(fallback))) group.valid = false;
        if(group.members.empty() && !group.opaque && !fallback.empty() && (had_members || all || all_proxies)) group.members.push_back(fallback);
        if(generated_empty.count(name)) group.members.clear();
    }
    // Mihomo resolves explicit references / pure group cycles before runtime
    // exclusions. Excluding a missing group must not validate an invalid file.
    for(auto &[start, model] : result) {
        std::set<std::string> active, complete;
        std::vector<std::pair<std::string, bool>> pending{{start, false}};
        while(!pending.empty()) {
            auto [name, leaving] = pending.back(); pending.pop_back();
            if(leaving) { active.erase(name); complete.insert(name); continue; }
            if(complete.count(name)) continue;
            if(!active.insert(name).second) { model.valid = false; break; }
            pending.emplace_back(name, true);
            if(!result.at(name).valid) model.valid = false;
            for(const auto &member : result.at(name).explicit_members) {
                if(groups.count(member)) pending.emplace_back(member, false);
                else if(!nodes.count(member) && !builtins.count(member)) model.valid = false;
            }
        }
    }
    return result;
}
}
#endif
