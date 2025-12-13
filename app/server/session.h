#pragma once

#include <string>
#include <chrono>
#include <iomanip>
#include <random>

class Session{
public:
    Session();
    //~Session();

    std::string generateSessionId();
    std::string createSession(const std::string& username);
    std::string getSessionUser(const std::string& sessionId);
    void destroySession(const std::string& sessionId);

    std::string getUser();
    auto getLastActivity();
    std::string getSession();
private:
    std::string username;
    std::string sessionID;
    std::chrono::time_point<std::chrono::system_clock> lastActivity;
    
    // 随机数生成器
    std::mt19937 generator;
    std::uniform_int_distribution<uint32_t> distribution;
};