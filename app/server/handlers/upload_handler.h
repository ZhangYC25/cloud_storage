#pragma once

#include <pistache/http.h>
#include <pistache/router.h>

#include "../../database/mysqlConnPool.h"
#include "../../database/redisConnPool.h"
#include "../../myfastdfs/fdfsConnPool.h"
#include "../../utils/threadPool.h"

class UploadHandler {
public:
    UploadHandler();

    void uploadCheck(const Pistache::Rest::Request& req,
                     Pistache::Http::ResponseWriter response);
    void upload(const Pistache::Rest::Request& req,
                Pistache::Http::ResponseWriter response);
    void largeInit(const Pistache::Rest::Request& req,
                   Pistache::Http::ResponseWriter response);
    void largeFileUpload(const Pistache::Rest::Request& req,
                         Pistache::Http::ResponseWriter response);
    void uploadLargeFileFinish(const Pistache::Rest::Request& req,
                               Pistache::Http::ResponseWriter response);

private:
    void mergeChunksAndUpload(const std::string& upload_id, const std::string& user);

    MySQLConnPool* _mysqlPool;
    RedisConnPool* _redisPool;
    FdfsConnPool* _fdfsPool;
    uploadThreadPool* _pthreadPool;
};
