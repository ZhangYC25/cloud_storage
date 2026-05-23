#include "email.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "../utils/asyncLogger.h"
#include "../utils/confRead.h"

namespace {
constexpr const char* kConfigPath = "../../conf/config.env";
constexpr const char* kSesHost = "ses.tencentcloudapi.com";
constexpr const char* kSesEndpoint = "https://ses.tencentcloudapi.com";
constexpr const char* kSesService = "ses";
constexpr const char* kSesVersion = "2020-10-02";
constexpr const char* kSesAction = "SendEmail";
}  // namespace

Email::Email(const std::string& toEmail, const std::string& username, const std::string& code)
    : _toEmail(toEmail), _username(username), _code(code) {
    secretId = loadConfigValue("TENCENT_SECRET_ID");
    secretKey = loadConfigValue("TENCENT_SECRET_KEY");
    templateID = loadConfigValue("TEMPLATE_ID");
    fromEmail = loadConfigValue("TENCENT_FROM_EMAIL");
    region = loadConfigValue("TENCENT_REGION");
    if (region.empty()) {
        region = "ap-hongkong";
    }
}

std::string Email::loadConfigValue(const std::string& key) {
    try {
        ConfigReader config(kConfigPath);
        return config.get(key);
    } catch (const std::exception& e) {
        MY_LOG_ERROR("Failed to load email config: ", e.what());
        return "";
    }
}

size_t Email::writeCallback(void* contents, size_t size, size_t nmemb, void* response) {
    auto* userResponse = static_cast<std::string*>(response);
    userResponse->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

std::string Email::bytesToHex(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string Email::sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

std::string Email::hmacSha256Raw(const std::string& key, const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    HMAC(EVP_sha256(),
         key.data(),
         static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()),
         data.size(),
         digest,
         &digestLen);
    return std::string(reinterpret_cast<char*>(digest), digestLen);
}

std::string Email::httpPost(const std::string& url,
                            const std::string& body,
                            const std::string& authorization,
                            int64_t timestamp,
                            const std::string& requestRegion) {
    CURL* curl = curl_easy_init();
    std::string response;

    if (!curl) {
        MY_LOG_ERROR("Failed to initialize curl for SES request");
        return R"({"Response":{"Error":{"Code":"ClientError","Message":"curl init failed"}}})";
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ("Host: " + std::string(kSesHost)).c_str());
    headers = curl_slist_append(headers, ("Authorization: " + authorization).c_str());
    headers = curl_slist_append(headers, ("X-TC-Action: " + std::string(kSesAction)).c_str());
    headers = curl_slist_append(headers,
                                ("X-TC-Timestamp: " + std::to_string(timestamp)).c_str());
    headers = curl_slist_append(headers, ("X-TC-Version: " + std::string(kSesVersion)).c_str());
    headers = curl_slist_append(headers, ("X-TC-Region: " + requestRegion).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        MY_LOG_ERROR("Tencent SES curl request failed: ", curl_easy_strerror(res));
        response = R"({"Response":{"Error":{"Code":"ClientError","Message":"curl request failed"}}})";
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

std::string Email::sendTencentSESEmail() {
    if (secretId.empty() || secretKey.empty() || fromEmail.empty() || templateID.empty()) {
        MY_LOG_ERROR("Tencent SES config missing, skip sending email to ", _toEmail);
        return R"({"Response":{"Error":{"Code":"ConfigError","Message":"Tencent SES config missing"}}})";
    }

    nlohmann::json payload;
    payload["FromEmailAddress"] = fromEmail;
    payload["Destination"] = nlohmann::json::array({_toEmail});
    payload["Subject"] = "【锦云存储】注册验证码";
    payload["Template"]["TemplateID"] = std::stoull(templateID);
    payload["Template"]["TemplateData"] =
        nlohmann::json{{"username", _username}, {"code", _code}}.dump();

    const std::string body = payload.dump();
    const int64_t timestamp = static_cast<int64_t>(std::time(nullptr));

    const std::string hashedPayload = sha256Hex(body);
    const std::string canonicalHeaders =
        "content-type:application/json\nhost:" + std::string(kSesHost) + "\n";
    const std::string signedHeaders = "content-type;host";
    const std::string canonicalRequest =
        std::string("POST\n/\n\n") + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedPayload;

    std::time_t now = timestamp;
    std::tm utcTime{};
    gmtime_r(&now, &utcTime);
    char dateBuffer[16] = {0};
    std::strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", &utcTime);
    const std::string date(dateBuffer);
    const std::string credentialScope = date + "/" + kSesService + "/tc3_request";

    const std::string stringToSign = std::string("TC3-HMAC-SHA256\n") +
                                     std::to_string(timestamp) + "\n" + credentialScope + "\n" +
                                     sha256Hex(canonicalRequest);

    const std::string secretDate = hmacSha256Raw("TC3" + secretKey, date);
    const std::string secretService = hmacSha256Raw(secretDate, kSesService);
    const std::string secretSigning = hmacSha256Raw(secretService, "tc3_request");
    const std::string signature = bytesToHex(
        reinterpret_cast<const unsigned char*>(hmacSha256Raw(secretSigning, stringToSign).data()),
        32);

    const std::string authorization =
        "TC3-HMAC-SHA256 Credential=" + secretId + "/" + credentialScope +
        ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;

    const std::string response = httpPost(kSesEndpoint, body, authorization, timestamp, region);
    MY_LOG_INFO("Tencent SES response for ", _toEmail, ": ", response);
    return response;
}
