#include "session_auth.h"

#include "../../database/redis.h"
#include "../../utils/asyncLogger.h"

namespace session_auth {

bool validateUploadSession(const Pistache::Rest::Request& req,
                           const std::string& upload_user_key,
                           std::shared_ptr<Redis> redis_ptr,
                           std::string& out_user) {
    out_user.clear();

    auto& cookies = req.cookies();
    if (!cookies.has("session")) {
        MY_LOG_ERROR("Upload request missing session cookie");
        return false;
    }

    std::string sessionId = cookies.get("session").value;
    if (sessionId.empty()) {
        MY_LOG_ERROR("Session cookie is empty");
        return false;
    }

    std::string session_user_key = "user:" + sessionId;
    out_user = redis_ptr->get(session_user_key);
    redis_ptr->expire(session_user_key, 600);
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

std::string getSessionUser(const std::string& sessionId,
                           std::shared_ptr<Redis> redis_ptr) {
    if (sessionId.empty()) {
        return "";
    }
    std::string session_user_key = "user:" + sessionId;
    std::string username = redis_ptr->get(session_user_key);
    if (!username.empty()) {
        redis_ptr->expire(session_user_key, 600);
    }
    return username;
}

}  // namespace session_auth
