#pragma once

#include <string>
#include <regex>
#include <unordered_set>
#include <iomanip>
#include <random>

bool isValidEmail(const std::string& email){
    static const std::regex pattern(
        R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)"
    );
    return std::regex_match(email, pattern);
}

// 辅助函数：检查密码强度（放在类外或作为私有静态函数）
bool isStrongPassword(const std::string& passwd) {
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
bool isWeakPassword(const std::string& passwd) {
    static const std::unordered_set<std::string> weakPasswords = {
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "1234567890", "qwerty", "abc123", "password123"
        // 可扩展...
    };
    std::string lowerPasswd = passwd;
    std::transform(lowerPasswd.begin(), lowerPasswd.end(), lowerPasswd.begin(), ::tolower);
    return weakPasswords.count(lowerPasswd) > 0;
}

std::string generateSixDigitCode() {
    static std::random_device rd;  // 仅用于种子
    static std::mt19937 gen(rd()); // 随机数生成器（静态，避免重复初始化）
    static std::uniform_int_distribution<> dis(0, 999999); // 均匀分布 [0, 999999]

    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << dis(gen);
    return oss.str();
}