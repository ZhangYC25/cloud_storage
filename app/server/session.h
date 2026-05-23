#pragma once

#include <chrono>
#include <memory>
#include <random>
#include <string>

#include <pistache/cookie.h>
#include <pistache/http.h>
#include <pistache/router.h>

class Redis;

class Session {
public:
    static constexpr int SESSION_TTL_SECONDS = 600;

    Session();

    std::string createSession(const std::string& username);
    void persistToRedis(std::shared_ptr<Redis> redis_ptr) const;

    std::string getUser() const;
    std::string getSession() const;
    auto getLastActivity() const { return lastActivity; }

    static std::string getSessionIdFromCookies(const Pistache::Http::CookieJar& cookies);
    static std::string getSessionUser(const std::string& sessionId,
                                      std::shared_ptr<Redis> redis_ptr);
    static bool validateUploadSession(const Pistache::Rest::Request& req,
                                      const std::string& upload_user_key,
                                      std::shared_ptr<Redis> redis_ptr,
                                      std::string& out_user);

private:
    std::string generateSessionId();

    std::string username;
    std::string sessionID;
    std::chrono::time_point<std::chrono::system_clock> lastActivity;

    std::mt19937 generator;
    std::uniform_int_distribution<uint32_t> distribution;
};
