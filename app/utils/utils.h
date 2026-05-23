#pragma once

#include <string>
#include <regex>
#include <unordered_set>
#include <iomanip>
#include <random>
#include <sstream>
#include <algorithm>

#include <cstdio>

inline bool isValidEmail(const std::string& email){
    static const std::regex pattern(
        R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)"
    );
    return std::regex_match(email, pattern);
}

// 辅助函数：检查密码强度（放在类外或作为私有静态函数）
inline bool isStrongPassword(const std::string& passwd) {
    if (passwd.length() < 8) {
        return false;
    }

    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
    const std::string specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?`~";

    for (char c : passwd) {
        if (std::islower(c)) hasLower = true;
        else if (std::isupper(c)) hasUpper = true;
        else if (std::isdigit(c)) hasDigit = true;
        else if (specialChars.find(c) != std::string::npos) hasSpecial = true;
    }

    // 要求：至少包含 3 类字符（例如：大小写+数字，或字母+数字+符号等）
    int categoryCount = hasLower + hasUpper + hasDigit + hasSpecial;
    return categoryCount >= 3;
}

// 可选：黑名单弱密码（简单示例，生产环境可加载文件或查表）
inline bool isWeakPassword(const std::string& passwd) {
    static const std::unordered_set<std::string> weakPasswords = {
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "1234567890", "qwerty", "abc123", "password123"
        // 可扩展...
    };
    std::string lowerPasswd = passwd;
    std::transform(lowerPasswd.begin(), lowerPasswd.end(), lowerPasswd.begin(), ::tolower);
    return weakPasswords.count(lowerPasswd) > 0;
}

inline std::string generateSixDigitCode() {
    static std::random_device rd;  // 仅用于种子
    static std::mt19937 gen(rd()); // 随机数生成器（静态，避免重复初始化）
    static std::uniform_int_distribution<> dis(0, 999999); // 均匀分布 [0, 999999]

    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << dis(gen);
    return oss.str();
}

// 生成纯数字的六位ID
static std::string generate_upload_id() {
    // 1. 初始化随机数生成器（仅初始化一次，避免重复）
    static std::random_device rd;  // 获取随机种子（硬件熵源）
    static std::mt19937 gen(rd()); // 梅森旋转算法，高性能随机数引擎
    // 2. 定义随机数范围：0 ~ 999999（六位数字的总范围）
    std::uniform_int_distribution<> dis(0, 999999);
    // 3. 生成随机数
    int random_num = dis(gen);
    // 4. 格式化为六位字符串（不足四位补前导零）
    std::stringstream ss;
    ss << std::setw(4) << std::setfill('0') << random_num;
    return ss.str();
}


inline std::string url_decode(const std::string& src) {
    std::string ret;
    ret.reserve(src.size());

    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            int val = 0;
            std::sscanf(src.substr(i + 1, 2).c_str(), "%x", &val);
            ret.push_back(static_cast<char>(val));
            i += 2;
        } else if (src[i] == '+') {
            ret.push_back(' ');  // 表单编码才会有，encodeURIComponent 通常不会
        } else {
            ret.push_back(src[i]);
        }
    }
    return ret;
}


inline void merge_and_upload_to_fastdfs(const std::string& upload_id, const std::string& temp_dir, const int& total_chunks) {
    try {
        // 1. 拼接文件
        std::string final_file = temp_dir + "/__final__.tmp";
        {
            std::ofstream ofs(final_file, std::ios::binary);
            for (int i = 0; i < total_chunks; ++i) {
                std::ifstream ifs(temp_dir + "/chunk_" + std::to_string(i), std::ios::binary);
                if (!ifs) throw std::runtime_error("Missing chunk " + std::to_string(i));
                ofs << ifs.rdbuf();
            }
        }

        // // 3. 上传 FastDFS
        // char file_id[256] = {0};
        // int result = fdfs_upload_by_filename(
        //     &g_tracker_group, nullptr, final_file.c_str(), nullptr, file_id, sizeof(file_id)
        // );

        // 4. 写结果到 Redis
        // nlohmann::json task;
        // if (result == 0 && strlen(file_id) > 0) {
        //     task["status"] = "success";
        //     task["file_id"] = std::string(file_id);
        //     task["url"] = build_fastdfs_url(file_id);
        // } else {
        //     task["status"] = "failed";
        //     task["error"] = "FastDFS upload failed, code=" + std::to_string(result);
        // }
        // redis_client.setex("task:" + upload_id, 3600, task.dump());

    } catch (const std::exception& e) {
        // nlohmann::json task;
        // task["status"] = "failed";
        // task["error"] = std::string("Exception: ") + e.what();
        //redis_client.setex("task:" + upload_id, 3600, task.dump());
    }

    // 5. 清理
    // try {
    //     redis_client.del("upload:" + upload_id);
    //     // 注意：temp_dir 可能已被删除，安全起见检查存在性
    //     auto session = redis_client.get("upload:" + upload_id);
    //     if (session) {
    //         auto j = nlohmann::json::parse(*session);
    //         std::string dir = j.value("temp_dir", "");
    //         if (!dir.empty() && std::filesystem::exists(dir)) {
    //             std::filesystem::remove_all(dir);
    //         }
    //     }
    // } catch (...) {}
}