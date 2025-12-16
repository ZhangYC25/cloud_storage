#include <iostream>
#include <stdexcept>
#include <fstream>
#include <sstream>

#include "confRead.h"

ConfigReader::ConfigReader(const std::string& filename) {
    parse_file(filename);
}

void ConfigReader::parse_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open config file: " + filename);
    }

    std::string line;
    while (std::getline(file, line)) {
        // 去除行首尾空白
        line = trim(line);

        // 跳过空行和注释
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // 查找 '=' 分隔符
        size_t pos = line.find('=');
        if (pos == std::string::npos) {
            continue; // 无效行
        }

        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));

        // 支持用双引号包裹值（可选）
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }

        config_[key] = value;
    }
    file.close();
}

std::string ConfigReader::get(const std::string& key, const std::string& default_value) const {
    auto it = config_.find(key);
    if (it != config_.end()) {
        return it->second;
    }
    return default_value;
}

int ConfigReader::get_int(const std::string& key, int default_value) const {
    auto it = config_.find(key);
    if (it != config_.end()) {
        try {
            return std::stoi(it->second);
        } catch (...) {
            // 如果转换失败，返回默认值
        }
    }
    return default_value;
}

std::string ConfigReader::trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}
