#pragma once
//#undef byte

#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>
#include <pistache/cookie.h>
#include <pistache/http_headers.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include "../database/mysqlConnPool.h"
#include "../myfastdfs/fdfsConnPool.h"
#include "../utils/threadPool.h"
#include "handlers/auth_handler.h"
#include "handlers/file_handler.h"
#include "handlers/upload_handler.h"

class Session;
class UploadFile;
class uploadThreadPool;

static int SESSION_TIMEOUT_SECONDS = 1800;

class Api{
public:
    ~Api();
    static std::shared_ptr<Api> getInstance();
    static void destroyInstance();
    void shutdown();

    void healthCheckLoop();
    void runConsistencyCheck();
    void setupRoutes();

    Pistache::Rest::Router& getRouter(){return this->router;};
    
private:
    Api();

    static std::shared_ptr<Api> _apiInstance;

    MySQLConnPool* _mysqlPool;
    FdfsConnPool* _fdfsPool;
    uploadThreadPool* _pthreadPool;
    AuthHandler _auth;
    FileHandler _file;
    UploadHandler _upload;
    Pistache::Rest::Router router;

    std::atomic<bool> running{true};
    std::mutex _mtx;
    std::condition_variable _cv;
    static std::mutex _instanceMtx;
};
