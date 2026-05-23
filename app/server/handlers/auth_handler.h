#pragma once

#include <pistache/http.h>
#include <pistache/router.h>

#include "../../database/mysqlConnPool.h"
#include "../../database/redisConnPool.h"

class AuthHandler {
public:
    AuthHandler();

    void loginUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    void registerEmail(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    void registerUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

private:
    MySQLConnPool* _mysqlPool;
    RedisConnPool* _redisPool;
};
