#pragma once

#include <string>

/*
home/zhangyc/tencentcloud-sdk-cpp/core/include/tencentcloud/core/profile/HttpProfile.h
home/zhangyc/tencentcloud-sdk-cpp/core/include/tencentcloud/core/profile/ClientProfile.h
home/zhangyc/tencentcloud-sdk-cpp/ses/include/tencentcloud/ses/v20201002/SesClient.h
home/zhangyc/tencentcloud-sdk-cpp/ses/include/tencentcloud/ses/v20201002/model/SendEmailRequest.h
*/

class Email{
public:
    Email(const std::string&, const std::string&, const std::string&);
    ~Email();
    
    std::string sendTencentSESEmail();

    std::string httpGet(const std::string &url);
    // 4. libcurl的回调函数（接收HTTP响应）
    static size_t writeCallback(void *contents, size_t size, size_t nmemb, void *response);

    // 3. 生成腾讯云API签名函数
    std::string generateTencentCloudSignature(const std::string &secretKey, const std::string &signStr);
    // 2. Base64编码函数（签名结果需要Base64编码）
    std::string base64Encode(const unsigned char *data, size_t length);
    // 1. URL编码函数（腾讯云API要求参数值URL编码）
    std::string urlEncode(const std::string &str);
private:
    std::string secretId;
    std::string secretKey;
    std::string templateID;
    std::string fromEmail;
    std::string _toEmail;
    std::string _username;
    std::string _code;
};