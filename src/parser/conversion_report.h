#ifndef CONVERSION_REPORT_H
#define CONVERSION_REPORT_H
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

struct SourceNodeIdentity;
struct Proxy;
// Only allocated for explicitly negotiated reports. Raw fields live for one
// request and are never serialized in diagnostic records or retained in caches.
struct ConversionInputNode
{
    YAML::Node input;
    const SourceNodeIdentity *identity = nullptr;
    std::string coverage = "FORMAT_UNVERIFIED";
    std::string uri_token;
    std::string reason = "FORMAT_UNVERIFIED";
    YAML::Node original;
};
struct ConversionInputSource
{
    std::string locator_sha256, content_sha256, fetch_context_sha256, provenance = "inline", format = "unknown";
    std::string reason = "SOURCE_FETCH_FAILED";
    std::vector<ConversionInputNode> nodes;
    YAML::Node root;
};
struct ConversionReport
{
    static constexpr size_t max_bytes = 16 * 1024 * 1024;
    static constexpr size_t max_nodes = 10000;
    static constexpr size_t max_fields = 100000;
    static constexpr size_t max_sources = 128;
    std::string nonce;
    std::vector<ConversionInputSource> sources;
    std::map<const SourceNodeIdentity *, std::string> emitted_names;
    std::map<std::string, YAML::Node> configured_defaults;
    std::string request_failure;
    size_t current = 0;
    size_t inventory_fields = 0, input_bytes = 0;
    explicit ConversionReport(std::string request_nonce);
    void beginSource(const std::string &locator);
    void sourceContent(const std::string &content);
    bool canParseSource() const;
    void bindClashNode(size_t index, const std::shared_ptr<SourceNodeIdentity> &identity);
    void bindUriNode(const std::string &token, const std::shared_ptr<SourceNodeIdentity> &identity);
    void emitted(const SourceNodeIdentity *identity, const std::string &name);
    void configureFilters(const std::vector<std::string> &include, const std::vector<std::string> &exclude);
    void configuredFilter(const Proxy &node, const std::vector<std::string> &include,
                          const std::vector<std::string> &exclude, bool dropped);
    std::string finish(const std::string &target, const std::string &output, int &status);
private:
    bool filters_configured = false;
    std::vector<std::string> include_filters, exclude_filters;
    struct FilterDecision {std::string kind; size_t ordinal;};
    std::map<const SourceNodeIdentity *, FilterDecision> filtered_nodes;
};
#endif
