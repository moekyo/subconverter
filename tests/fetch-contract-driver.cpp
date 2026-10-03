// Loopback-only test driver; links the real production fetch and file code.
#include <iostream>
#include <stdexcept>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "handler/settings.h"
#include "handler/webget.h"
Settings global;
// Keep test output machine-readable. The logger is the only service stub.
void writeLog(int, const std::string &, int) {}
int main(int argc, char **argv) {
    if (argc != 9) return 2;
    global.APIMode = std::stoi(argv[5]);
    global.serveCacheOnFetchFail = true;
    global.logLevel = LOG_LEVEL_ERROR;
    global.maxAllowedDownloadSize = 1024 * 1024;
    string_icase_map headers;
    if (std::string(argv[7]) != "-") headers["Authorization"] = argv[7];
    std::string body, response_headers;
    int status = -1;
    int transport = -1, upstream = -1;
    bool force = std::stoi(argv[6]);
    unsigned int ttl = std::stoul(argv[4]);
    if (std::string(argv[1]) == "raw") {
        FetchArgument arg{HTTP_GET, argv[2], argv[3], nullptr, &headers, nullptr, ttl, false, force};
        FetchResult result{&status, &body, &response_headers, nullptr};
        status = webGet(arg, result);
        transport = result.transport_code;
        upstream = result.upstream_http_status;
    } else {
        body = webGet(argv[2], argv[3], ttl, &response_headers, &headers, force);
    }
    nlohmann::json j;
    j["body"] = body;
    j["headers"] = response_headers;
    j["status"] = status;
    j["transport"] = transport;
    j["upstream_status"] = upstream;
    j["curl_runtime"] = curl_version_info(CURLVERSION_NOW)->version;
    j["curl_headers"] = LIBCURL_VERSION;
    j["label"] = argv[8];
    std::cout << j.dump() << std::endl;
}
