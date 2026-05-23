#include "session.h"

#include <iomanip>
#include <sstream>

#include "../database/redis.h"
#include "../utils/asyncLogger.h"

Session::Session() {
    std::random_device rd;
    generator.seed(rd());
}

std::string Session::generateSessionId() {
    std::stringstream ss;
    for (int i = 0; i < 4; ++i) {
        uint32_t random_value = distribution(generator);
        ss << std::hex << std::setw(8) << std::setfill('0') << random_value;
    }
    return ss.str();
}

std::string Session::createSession(const std::string& username) {
    std::string sessionId = generateSessionId();
    this->username = username;
    this->lastActivity = std::chrono::system_clock::now();
    this->sessionID = sessionId;
    return this->sessionID;
}

void Session::persistToRedis(std::shared_ptr<Redis> redis_ptr) const {
    if (sessionID.empty() || username.empty()) {
        return;
    }
    std::string key = "user:" + sessionID;
    redis_ptr->set(key, username, SESSION_TTL_SECONDS);
}

std::string Session::getUser() const { return username; }

std::string Session::getSession() const { return sessionID; }

std::string Session::getSessionIdFromCookies(const Pistache::Http::CookieJar& cookies) {
    if (!cookies.has("session")) {
        return "";
    }
    return cookies.get("session").value;
}

std::string Session::getSessionUser(const std::string& sessionId,
                                    std::shared_ptr<Redis> redis_ptr) {
    if (sessionId.empty()) {
        return "";
    }
    std::string session_user_key = "user:" + sessionId;
    std::string username = redis_ptr->get(session_user_key);
    if (!username.empty()) {
        redis_ptr->expire(session_user_key, SESSION_TTL_SECONDS);
    }
    return username;
}

bool Session::validateUploadSession(const Pistache::Rest::Request& req,
                                    const std::string& upload_user_key,
                                    std::shared_ptr<Redis> redis_ptr,
                                    std::string& out_user) {
    out_user.clear();

    std::string sessionId = getSessionIdFromCookies(req.cookies());
    if (sessionId.empty()) {
        MY_LOG_ERROR("Upload request missing or empty session cookie");
        return false;
    }

    out_user = getSessionUser(sessionId, redis_ptr);
    if (out_user.empty()) {
        MY_LOG_ERROR("Invalid or expired session: ", sessionId);
        return false;
    }

    if (!upload_user_key.empty()) {
        std::string key_owner = redis_ptr->get(upload_user_key);
        if (key_owner != out_user) {
            MY_LOG_ERROR("Upload session mismatch: session user='", out_user,
                         "', but upload_user_key belongs to='", key_owner, "'");
            return false;
        }
    }
    return true;
}
