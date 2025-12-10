#pragma once
//#undef byte

#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <bcrypt.h>
#include <unordered_set>

#include "database/mysqlConnPool.h"
#include "myfastdfs/fdfsConnPool.h"
#include "database/redis.h"


// typedef struct userInfo_t{
//     int64_t user_id;
//     const char* user_name;

//     bool operator==(const userInfo& other){
//         return this->user_id == other.user_id;
//     }
// } userInfo;

// namespace std {
//     template<>
//     struct hash<userInfo> {
//         // 重载 () 运算符，计算哈希值（核心：基于唯一标识，比如id）
//         size_t operator()(const userInfo& user) const {
//             // 简单场景：直接用id的哈希（如果id是唯一键）
//             return hash<int64_t>()(user.user_id);
//         }
//     };
// }


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

    void deleteFiles(const std::string& url, const std::string& md5);

    Pistache::Rest::Router& getRouter(){return this->router;};

private:
    Api();
    static std::shared_ptr<Api> _apiInstance;
    MySQLConnPool* _mysqlPool;
    FdfsConnPool* _fdfsPool;
    //std::unordered_set<userInfo> _userSet;
    using json = nlohmann::json;
    Pistache::Rest::Router router;
};