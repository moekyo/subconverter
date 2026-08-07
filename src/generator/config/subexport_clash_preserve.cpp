#include <string>

#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "utils/logger.h"

// CMake compiles subexport.cpp with proxyToClash renamed to these legacy
// symbols. Keeping the original implementation intact lets this wrapper add one
// generic behavior: base-file proxy groups survive custom-group generation.
std::string proxyToClashLegacy(
    std::vector<Proxy> &nodes,
    const std::string &base_conf,
    std::vector<RulesetContent> &ruleset_content_array,
    const ProxyGroupConfigs &extra_proxy_group,
    bool clashR,
    extra_settings &ext);

void proxyToClashLegacy(
    std::vector<Proxy> &nodes,
    YAML::Node &yamlnode,
    const ProxyGroupConfigs &extra_proxy_group,
    bool clashR,
    extra_settings &ext);

namespace
{
YAML::Node cloneSequence(const YAML::Node &node)
{
    if(!node.IsSequence())
        return YAML::Node();
    return YAML::Load(YAML::Dump(node));
}

void mergeGeneratedGroups(
    YAML::Node &yamlnode,
    YAML::Node preserved_groups,
    bool clash_new_field_name)
{
    if(!preserved_groups.IsSequence())
        return;

    const char *group_key = clash_new_field_name ? "proxy-groups" : "Proxy Group";
    YAML::Node generated_groups = yamlnode[group_key];
    if(!generated_groups.IsSequence())
    {
        yamlnode[group_key] = preserved_groups;
        return;
    }

    for(const auto &generated_group : generated_groups)
    {
        if(!generated_group["name"].IsDefined())
        {
            preserved_groups.push_back(generated_group);
            continue;
        }

        const std::string generated_name = generated_group["name"].as<std::string>();
        bool replaced = false;
        for(auto &&preserved_group : preserved_groups)
        {
            if(!preserved_group["name"].IsDefined())
                continue;
            if(preserved_group["name"].as<std::string>() == generated_name)
            {
                preserved_group.reset(generated_group);
                replaced = true;
                break;
            }
        }
        if(!replaced)
            preserved_groups.push_back(generated_group);
    }

    yamlnode[group_key] = preserved_groups;
}
}

void proxyToClash(
    std::vector<Proxy> &nodes,
    YAML::Node &yamlnode,
    const ProxyGroupConfigs &extra_proxy_group,
    bool clashR,
    extra_settings &ext)
{
    const char *group_key = ext.clash_new_field_name ? "proxy-groups" : "Proxy Group";
    YAML::Node preserved_groups = cloneSequence(yamlnode[group_key]);

    proxyToClashLegacy(nodes, yamlnode, extra_proxy_group, clashR, ext);

    if(ext.nodelist)
        return;
    mergeGeneratedGroups(yamlnode, preserved_groups, ext.clash_new_field_name);
}

std::string proxyToClash(
    std::vector<Proxy> &nodes,
    const std::string &base_conf,
    std::vector<RulesetContent> &ruleset_content_array,
    const ProxyGroupConfigs &extra_proxy_group,
    bool clashR,
    extra_settings &ext)
{
    YAML::Node yamlnode;

    try
    {
        yamlnode = YAML::Load(base_conf);
    }
    catch(std::exception &e)
    {
        writeLog(
            0,
            std::string("Clash base loader failed with error: ") + e.what(),
            LOG_LEVEL_ERROR);
        return "";
    }

    proxyToClash(nodes, yamlnode, extra_proxy_group, clashR, ext);

    if(ext.nodelist)
        return YAML::Dump(yamlnode);

    if(!ext.enable_rule_generator)
        return YAML::Dump(yamlnode);

    if(!ext.managed_config_prefix.empty() || ext.clash_script)
    {
        if(yamlnode["mode"].IsDefined())
        {
            if(ext.clash_new_field_name)
                yamlnode["mode"] = ext.clash_script ? "script" : "rule";
            else
                yamlnode["mode"] = ext.clash_script ? "Script" : "Rule";
        }

        renderClashScript(
            yamlnode,
            ruleset_content_array,
            ext.managed_config_prefix,
            ext.clash_script,
            ext.overwrite_original_rules,
            ext.clash_classical_ruleset);
        return YAML::Dump(yamlnode);
    }

    std::string output_content = rulesetToClashStr(
        yamlnode,
        ruleset_content_array,
        ext.overwrite_original_rules,
        ext.clash_new_field_name);
    output_content.insert(0, YAML::Dump(yamlnode));
    return output_content;
}
