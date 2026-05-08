#pragma once
//#undef byte

#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <pistache/cookie.h>
#include <pistache/http_headers.h>
#include <bcrypt.h>
#include <unordered_set>
#include <nlohmann/json.hpp>
#include <filesystem>
#include "../database/mysqlConnPool.h"
#include "../database/redisConnPool.h"
#include "../myfastdfs/fdfsConnPool.h"
#include "../utils/threadPool.h"

class Session;
class UploadFile;
class uploadThreadPool;

static int SESSION_TIMEOUT_SECONDS = 1800;

class Api{
public:
    ~Api();
    //void destroyed();
    static std::shared_ptr<Api> getInstance();
    static void destroyInstance();
    void shutdown();


    void healthCheckLoop();
    void runConsistencyCheck();
    // ============= route ========================
    void setupRoutes();

    //============ POST /register ============
    void registerUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    void registerEmail(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    // ========= POST /login =========
    void loginUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    // =========== POST / up and check
    void uploadCheck(const  Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    // ================= POST / upload 
    void upload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    
    // ================== POST / large file upload
    void largeInit(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    void largeFileUpload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    void uploadLargeFileFinish(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    
    void queryFileURL(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);
    // ================== GET / queryUserFiles ===========
    void queryUserFiles(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response);

    // ================== DELETE / delete
    void deleteCheck(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response);

    void deleteFiles(const std::string& url);

    void mergeChunksAndUpload(const std::string& upload_id, const std::string& user);

    Pistache::Rest::Router& getRouter(){return this->router;};

    //=============== Session ==================
    std::string getSessionUser(const std::string& sessionId);
    
private:
    Api();

    static std::shared_ptr<Api> _apiInstance;

    MySQLConnPool* _mysqlPool;
    FdfsConnPool* _fdfsPool;
    RedisConnPool* _redisPool;
    uploadThreadPool* _pthreadPool;
    Pistache::Rest::Router router;
    using json = nlohmann::json;

    std::atomic<bool> running{true};
    std::mutex _mtx;                 // 配合条件变量使用
    std::condition_variable _cv;
    static std::mutex _instanceMtx;

    //================== Session ===============
    bool validateUploadSession(const Pistache::Rest::Request& req, const std::string& upload_id,
                            std::shared_ptr<Redis> redis, std::string& out_user);
};
