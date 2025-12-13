#pragma once
//#undef byte

#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <pistache/cookie.h>
#include <bcrypt.h>
#include <unordered_set>
#include <nlohmann/json.hpp>

#include "../database/mysqlConnPool.h"
#include "../database/redisConnPool.h"
#include "../myfastdfs/fdfsConnPool.h"

class Session;

static int SESSION_TIMEOUT_SECONDS = 1800;

class Api{
public:
    ~Api();
    //void destroyed();
    static std::shared_ptr<Api> getInstance();
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

    // ================== GET / queryUserFiles ===========
    void queryUserFiles(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response);

    // ================== DELETE / delete
    void deleteCheck(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    void deleteFiles(const std::string& url);

    Pistache::Rest::Router& getRouter(){return this->router;};

    //=============== Session ==================
    std::string getSessionUser(const std::string& sessionId);
    
private:
    Api();

    static std::shared_ptr<Api> _apiInstance;

    MySQLConnPool* _mysqlPool;
    FdfsConnPool* _fdfsPool;
    RedisConnPool* _redisPool;

    Pistache::Rest::Router router;
    using json = nlohmann::json;
    //================== Session ===============
    //<user, Session>
    //<Session session -> getUsername(), Session>
    //手动修改 短Session；Redis 自动释放过期session
    std::unordered_map<std::string, std::shared_ptr<Session>> _sessions;
};