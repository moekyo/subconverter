#ifndef CONVERSION_URI_H
#define CONVERSION_URI_H
#include <string>
#include <yaml-cpp/yaml.h>
// Independent URI-to-semantic-field inventory. It never calls a production
// protocol constructor/parser/exporter or reads its accepted Proxy objects.
bool inventoryShareUri(const std::string &uri,YAML::Node &fields,YAML::Node &original_fields,std::string &reason);
#endif
