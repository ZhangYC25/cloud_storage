#pragma once

#include <string>
#include <unordered_map>
class ConfigReader{
public:
    explicit ConfigReader(const std::string& filename);
    std::string get(const std::string& key, const std::string& default_value = "") const;
    int get_int(const std::string& key, int default_value = 0) const;

private:
    std::unordered_map<std::string, std::string> config_;
    void parse_file(const std::string& filename);
    std::string trim(const std::string& str);
};