#include "file_handler.h"

#include <iostream>

#include <nlohmann/json.hpp>

#include "../session.h"
#include "../common/fdfs_ops.h"
#include "../../utils/asyncLogger.h"

FileHandler::FileHandler()
    : _mysqlPool(MySQLConnPool::getInstance()),
      _redisPool(RedisConnPool::getInstance()),
      _fdfsPool(FdfsConnPool::getInstance()) {}

void FileHandler::queryFileURL(const Pistache::Rest::Request& req,
                               Pistache::Http::ResponseWriter response) {
    using json = nlohmann::json;

    std::shared_ptr<Redis> redis_ptr = _redisPool->getConnection();
    try {
        auto body = req.body();
        json j = json::parse(body);

        std::string md5 = j.value("md5", "");
        std::string upload_id = j.value("upload_id", "");

        if (md5.empty() || upload_id.empty()) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"missing md5 or upload_id"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        std::string status_key = "upload:" + upload_id + ":status";
        std::string upload_user_key = md5 + upload_id + ":ID";

        std::string user = "";
        if (!Session::validateUploadSession(req, upload_user_key, redis_ptr, user)) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"invalid session"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        std::string upload_status = redis_ptr->get(status_key);

        if (upload_status == "mergeing") {
            json res = {{"success", true}, {"status", "mergeing"}};
            response.send(Pistache::Http::Code::Ok, res.dump(), MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        if (upload_status == "uploadfail") {
            response.send(Pistache::Http::Code::Ok,
                          R"({"success":false,"error":"文件合并失败"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        if (upload_status != "finish") {
            response.send(Pistache::Http::Code::Ok,
                          R"({"success":false,"error":"invalid merging"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        std::string URL = redis_ptr->get(md5);
        if (URL != "") {
            URL = "https://goodfloat.cloud/" + URL;
        }
        redis_ptr->expire(md5, 3600);
        json response_json = {{"success", true}, {"status", "finish"}, {"url", URL}};

        response.headers().add<Pistache::Http::Header::ContentType>(
            Pistache::Http::Mime::MediaType("application/json"));
        response.send(Pistache::Http::Code::Ok, response_json.dump());
    } catch (const nlohmann::json::parse_error&) {
        response.send(Pistache::Http::Code::Bad_Request,
                      R"({"success":false,"message":"invalid json"})",
                      MIME(Application, Json));
    } catch (const std::exception& e) {
        MY_LOG_ERROR("Error in queryFileURL: ", e.what());
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"server error"})",
                      MIME(Application, Json));
    }
    _redisPool->releaseConnection(redis_ptr);
}

void FileHandler::queryUserFiles(const Pistache::Http::Request& req,
                                 Pistache::Http::ResponseWriter response) {
    using json = nlohmann::json;

    try {
        std::string sessionId = Session::getSessionIdFromCookies(req.cookies());
        if (sessionId.empty()) {
            MY_LOG_ERROR("queryUserFiles invalid session");
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"invalid session!"})",
                          MIME(Application, Json));
            return;
        }

        std::shared_ptr<Redis> redis_ptr = _redisPool->getConnection();
        std::string username = Session::getSessionUser(sessionId, redis_ptr);
        _redisPool->releaseConnection(redis_ptr);

        if (username.empty()) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"invalid session!"})",
                          MIME(Application, Json));
            return;
        }

        json array = json::array();

        std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
        mysql_ptr->queryUserFiles(username, array);
        _mysqlPool->releaseConnection(mysql_ptr);

        std::string jsonString = array.dump();

        response.headers().add<Pistache::Http::Header::ContentType>(
            Pistache::Http::Mime::MediaType("application/json"));
        response.send(Pistache::Http::Code::Ok, jsonString);
    } catch (const std::exception& e) {
        MY_LOG_ERROR("Error in queryUserFiles: ", e.what());
        response.send(Pistache::Http::Code::Internal_Server_Error, "Server error");
    }
}

void FileHandler::deleteCheck(const Pistache::Rest::Request& req,
                              Pistache::Http::ResponseWriter response) {
    std::shared_ptr<Redis> redis_ptr = _redisPool->getConnection();
    std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
    try {
        auto idOpt = req.query().get("id");
        if (!idOpt) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"Missing user or id"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }
        const std::string md5 = idOpt.value();

        const std::string sessionId = Session::getSessionIdFromCookies(req.cookies());
        if (sessionId.empty()) {
            MY_LOG_ERROR("deleteCheck invalid session");
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"invalid session!"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        const std::string user = Session::getSessionUser(sessionId, redis_ptr);
        if (user.empty() || md5.empty()) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"success":false,"message":"Missing user or id"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (!mysql_ptr->isInUserList(md5, user)) {
            response.send(Pistache::Http::Code::Not_Found,
                          R"({"success":false,"message":"file not found"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (!mysql_ptr->beginTransaction()) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"数据库事务开启失败"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        int count = 0;
        std::string url;
        if (!mysql_ptr->getCount(md5, count, url)) {
            mysql_ptr->rollback();
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"文件记录不存在"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (!mysql_ptr->deleteUserFile(user, md5)) {
            mysql_ptr->rollback();
            MY_LOG_ERROR("deleteCheck deleteUserFile failed: user=", user, " md5=", md5);
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"删除用户文件记录失败"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (!mysql_ptr->updateCount(md5, -1)) {
            mysql_ptr->rollback();
            MY_LOG_ERROR("deleteCheck updateCount failed: md5=", md5);
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"更新引用计数失败"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        const bool purge_storage = (count <= 1);
        if (purge_storage) {
            if (!mysql_ptr->deleteSysFile(md5)) {
                mysql_ptr->rollback();
                MY_LOG_ERROR("deleteCheck deleteSysFile failed: md5=", md5);
                response.send(Pistache::Http::Code::Internal_Server_Error,
                              R"({"success":false,"message":"删除系统文件记录失败"})",
                              MIME(Application, Json));
                _redisPool->releaseConnection(redis_ptr);
                _mysqlPool->releaseConnection(mysql_ptr);
                return;
            }
        }

        if (!mysql_ptr->commit()) {
            mysql_ptr->rollback();
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"数据库提交失败"})",
                          MIME(Application, Json));
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        // DB 已提交；Redis / FastDFS 失败只记日志，不影响接口成功（物理文件可由健康检查兜底）
        if (purge_storage) {
            redis_ptr->del(md5);
            redis_ptr->del("md5:" + md5);

            if (!url.empty()) {
                fdfs_ops::deleteFile(_fdfsPool, url);
            } else {
                MY_LOG_ERROR("deleteCheck skip fdfs delete: empty url for md5=", md5);
            }

            MY_LOG_INFO("deleteCheck purged file: user=", user, " md5=", md5);
            response.send(Pistache::Http::Code::Ok,
                          R"({"success":true,"message":"File deleted successfully"})",
                          MIME(Application, Json));
        } else {
            MY_LOG_INFO("deleteCheck removed user reference: user=", user, " md5=", md5);
            response.send(Pistache::Http::Code::Ok,
                          R"({"success":true,"message":"user_file_list deleted"})",
                          MIME(Application, Json));
        }
    } catch (const std::exception& e) {
        MY_LOG_ERROR("deleteCheck exception: ", e.what());
        if (mysql_ptr) {
            mysql_ptr->rollback();
        }
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"服务器异常"})",
                      MIME(Application, Json));
    }
    _redisPool->releaseConnection(redis_ptr);
    _mysqlPool->releaseConnection(mysql_ptr);
}
