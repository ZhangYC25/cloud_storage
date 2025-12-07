#pragma once
//#undef byte

#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <nlohmann/json.hpp>
#include <bcrypt.h>

#include "database/mysqlConnPool.h"
#include "myfastdfs/fdfsConnPool.h"
#include "database/redis.h"

class Api{
public:
    Api();
    ~Api() = default;

    // ============= route ========================
    void setupRoutes();

    //============ POST /register ============
    void registerUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    // ========= POST /login =========
    void loginUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    // =========== POST / up and check
    void uploadCheck(const  Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    // ================= POST / upload 
    void upload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);


    Pistache::Rest::Router& getRouter(){return this->router;};

private:
    MySQLConnPool* _mysqlPool;
    FdfsConnPool* _fdfsPool;
    using json = nlohmann::json;
    Pistache::Rest::Router router;
};