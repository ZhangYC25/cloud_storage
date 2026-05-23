#pragma once

#include <memory>
#include <string>

#include <pistache/http.h>
#include <pistache/router.h>

class Redis;

namespace session_auth {

bool validateUploadSession(const Pistache::Rest::Request& req,
                           const std::string& upload_user_key,
                           std::shared_ptr<Redis> redis_ptr,
                           std::string& out_user);

std::string getSessionUser(const std::string& sessionId,
                           std::shared_ptr<Redis> redis_ptr);

}  // namespace session_auth
