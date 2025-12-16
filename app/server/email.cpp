#include <random>
#include <string>
#include <iomanip>
#include <sstream>
#include <curl/curl.h>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <map>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdlib>
#include"email.h"
#include "../utils/confRead.h"

Email::Email(const std::string& toEmail, 
                const std::string& username,
                const std::string& code){
                    _toEmail = toEmail;
                    _username = username;
                    _code = code;
                    ConfigReader config("../../conf/config");
                    secretId = config.get("TENCENT_SECRET_ID");
                    secretKey = config.get("TENCENT_SECRET_KEY");
                    templateID = config.get("TEMPLATE_ID");
                    fromEmail = config.get("TENCENT_REGION");
                }
Email::~Email(){};
std::string Email::httpGet(const std::string &url) {
    CURL *curl = curl_easy_init();
    std::string response;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 验证SSL证书（生产环境建议开启）
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl请求失败: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    } else {
        std::cerr << "初始化curl失败" << std::endl;
    }

    return response;
}

// 4. libcurl的回调函数（接收HTTP响应）
size_t Email::writeCallback(void *contents, size_t size, size_t nmemb, void *response) {
    // 
    std::string *userrp = static_cast<std::string*>(response);
    userrp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// 1. URL编码函数（腾讯云API要求参数值URL编码）
std::string Email::urlEncode(const std::string &str) {
    std::string result;
    for (char c : str) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
        } else {
            result += '%';
            char hex[3];
            snprintf(hex, sizeof(hex), "%02X", (unsigned char)c);
            result += hex;
        }
    }
    return result;
}

// 2. Base64编码函数（签名结果需要Base64编码）
std::string Email::base64Encode(const unsigned char *data, size_t length) {
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, length);
    BIO_flush(bio);

    char *buffer;
    long len = BIO_get_mem_data(bio, &buffer);
    std::string result(buffer, len);
    BIO_free_all(bio);

    // 去除Base64末尾的换行符
    result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
    return result;
}

// 3. 生成腾讯云API签名函数
std::string Email::generateTencentCloudSignature(const std::string &secretKey, const std::string &signStr) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen;

    // HMAC-SHA1加密
    HMAC(EVP_sha1(), secretKey.c_str(), secretKey.length(),
         (const unsigned char *)signStr.c_str(), signStr.length(),
         digest, &digestLen);

    // Base64编码
    return base64Encode(digest, digestLen);
}

std::string Email::sendTencentSESEmail(){
            // 1. 固定参数配置
        std::string action = "SendEmail";
        std::string version = "2020-10-02";
        std::string region = "ap-hongkong"; // 地域：广州/香港等
        std::time_t timestamp = std::time(nullptr); // 时间戳（秒）
        int nonce = std::rand(); // 随机数

        // 2. 构造模板变量（JSON格式）
        std::string templateData = "{\"username\":\"" + _username + "\",\"code\":\"" + _code + "\"}";

        // 3. 存储所有参数（key-value，用于排序）
        std::map<std::string, std::string> params;
        params["Action"] = action;
        params["Destination.0"] = _toEmail;
        params["FromEmailAddress"] = fromEmail;
        params["Nonce"] = std::to_string(nonce);
        params["Region"] = region;
        params["SecretId"] = secretId;
        params["Subject"] = "【锦云存储】注册验证码"; // 邮件主题
        params["Template.TemplateData"] = templateData;
        params["Template.TemplateID"] = templateID;
        params["Timestamp"] = std::to_string(timestamp);
        params["Version"] = version;

        // 4. 按字典序拼接参数（key=value&key=value...）
        std::string sortedParams;
        for (const auto &pair : params) {
            if (!sortedParams.empty()) {
                sortedParams += "&";
            }
            sortedParams += pair.first + "=" + urlEncode(pair.second);
        }

        // 5. 生成待签名字符串（GET + 域名 + 路径 + ? + 参数）
        std::string signStr = "GETses.tencentcloudapi.com/?" + sortedParams;
        //std::string signStr = "GETses.tencentcloudapi.com/" + "?" + sortedParams;
        // 6. 生成签名并URL编码
        std::string signature = generateTencentCloudSignature(secretKey, signStr);
        std::string encodedSignature = urlEncode(signature);

        // 7. 构造最终请求URL
        std::string requestUrl = "https://ses.tencentcloudapi.com/?" + sortedParams + "&Signature=" + encodedSignature;

        // 8. 发送HTTP GET请求并返回响应
        return httpGet(requestUrl);
    }

