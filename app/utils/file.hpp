// upload_session.h
#include <string>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>
#include <iostream>
#include <random>
#include <iomanip>


const size_t CHUNK_SIZE = 256 * 1024; // 256KB
const std::string TEMP_BASE_DIR = "/tmp/uploads";

class UploadFile {
public:
    UploadFile(const std::string& filename, const uint& size, const std::string& path){
        _filename = filename;
        _uploaded_chunks.clear();
        _temp_dir = path;
        _total_size = (size + CHUNK_SIZE -1) / CHUNK_SIZE;
    }

    UploadFile(){}

    // 序列化为 JSON（用于 Redis）
    std::string serialize() const {
        nlohmann::json j;
        j["filename"] = _filename;
        j["total_size"] = _total_size;
        // 序列化：将 unordered_set 转为 JSON 数组（nlohmann/json 支持直接序列化）
        j["uploaded_chunks"] = _uploaded_chunks;
        j["temp_dir"] = _temp_dir;
        return j.dump();
    }

    bool is_complete(int total_chunks) const {
        return _uploaded_chunks.size() == static_cast<size_t>(total_chunks);
    }

    // 友元函数声明
    //friend void deserialize(UploadFile& obj, const std::string& json_str);

//private:
    std::string _filename;
    uint64_t _total_size;
    std::unordered_set<int> _uploaded_chunks;
    std::string _temp_dir; // e.g., "/tmp/uploads/a1b2c3d4"
};

// 反序列化函数定义（处理异常+兼容 unordered_set）
std::shared_ptr<UploadFile> deserialize(const std::string& json_str) {
    try {
        std::shared_ptr<UploadFile> obj = std::make_shared<UploadFile>();
        auto j = nlohmann::json::parse(json_str);
        obj -> _filename = j.value("filename", "");
        obj -> _total_size = j.value("total_size", 0ULL); // 0ULL 匹配 uint64_t 类型
        obj -> _temp_dir = j.value("temp_dir", "");

        // 处理 unordered_set 反序列化
        // 解决 nlohmann/json 对 unordered_set 直接 get 的兼容性问题
        if (j.contains("uploaded_chunks") && j["uploaded_chunks"].is_array()) {
            // 先将 JSON 数组转为 std::vector<int>，再构造 std::unordered_set
            std::vector<int> chunks = j["uploaded_chunks"].get<std::vector<int>>();
            obj -> _uploaded_chunks = std::unordered_set<int>(chunks.begin(), chunks.end());
        } else {
            // 键不存在或类型错误时，清空集合
            obj -> _uploaded_chunks.clear();
        }
        return obj;
    } catch (const nlohmann::json::exception& e) {
        // 捕获 JSON 解析/反序列化异常，可根据需求处理（如抛出自定义异常、返回错误等）
        throw std::runtime_error("JSON deserialize failed: " + std::string(e.what()));
    }
}