
#include "session.h"

Session::Session() {
    // 初始化随机数生成器
    std::random_device rd;
    generator.seed(rd());
}

std::string Session::generateSessionId(){
    // 使用 mersenne twister 算法生成 128 位随机数，并转换为十六进制字符串
    std::stringstream ss;
    for (int i = 0; i < 4; ++i) { // 生成 4 个 32-bit 随机数
        uint32_t random_value = distribution(generator);
        ss << std::hex << std::setw(8) << std::setfill('0') << random_value;
    }
    return ss.str();
}

std::string Session::createSession(const std::string& username){
    std::string sessionId = generateSessionId();
    this -> username = username;
    this -> lastActivity = std::chrono::system_clock::now();
    this -> sessionID = sessionId;
    return this -> sessionID;
}

// void Session::destroySession(const std::string& sessionId){
    
// }

std::string Session::getUser(){return this -> username;}
auto Session::getLastActivity(){return this -> lastActivity;}
std::string Session::getSession(){return this -> sessionID;}
