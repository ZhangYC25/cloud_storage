#pragma once

#include <pistache/http.h>
#include <pistache/router.h>

#include "../../database/mysqlConnPool.h"
#include "../../database/redisConnPool.h"
#include "../../myfastdfs/fdfsConnPool.h"

class FileHandler {
public:
    FileHandler();

    void queryUserFiles(const Pistache::Http::Request& req,
                        Pistache::Http::ResponseWriter response);
    void deleteCheck(const Pistache::Rest::Request& req,
                     Pistache::Http::ResponseWriter response);
    void queryFileURL(const Pistache::Rest::Request& req,
                      Pistache::Http::ResponseWriter response);

private:
    MySQLConnPool* _mysqlPool;
    RedisConnPool* _redisPool;
    FdfsConnPool* _fdfsPool;
};
