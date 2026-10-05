#include <string>

#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "utils/logger.h"

// CMake compiles subexport.cpp with proxyToClash renamed to these legacy
// symbols. This wrapper exposes the public overloads and renders rules after
// the implementation has constructed and validated the final proxy groups.
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

void proxyToClash(
    std::vector<Proxy> &nodes,
    YAML::Node &yamlnode,
    const ProxyGroupConfigs &extra_proxy_group,
    bool clashR,
    extra_settings &ext)
{
    // The implementation constructs, validates and writes the final groups.
    // Do not merge another copy after the chain check.
    proxyToClashLegacy(nodes, yamlnode, extra_proxy_group, clashR, ext);
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
    if(ext.chain_conversion_failed) return "";

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
