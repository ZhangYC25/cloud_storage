#pragma once

#include <string>

class Email {
public:
    Email(const std::string& toEmail, const std::string& username, const std::string& code);
    ~Email() = default;

    std::string sendTencentSESEmail();

private:
    static std::string loadConfigValue(const std::string& key);
    static std::string sha256Hex(const std::string& data);
    static std::string hmacSha256Raw(const std::string& key, const std::string& data);
    static std::string bytesToHex(const unsigned char* data, size_t length);
    static std::string httpPost(const std::string& url,
                                const std::string& body,
                                const std::string& authorization,
                                int64_t timestamp,
                                const std::string& region);
    static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* response);

    std::string secretId;
    std::string secretKey;
    std::string templateID;
    std::string fromEmail;
    std::string region;
    std::string _toEmail;
    std::string _username;
    std::string _code;
};
