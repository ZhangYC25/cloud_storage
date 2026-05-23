#include "auth_handler.h"

#include <iostream>

#include <bcrypt.h>
#include <nlohmann/json.hpp>

#include "../email.h"
#include "../session.h"
#include "../../utils/utils.h"
#include "../../utils/asyncLogger.h"

AuthHandler::AuthHandler()
    : _mysqlPool(MySQLConnPool::getInstance()),
      _redisPool(RedisConnPool::getInstance()) {}

void AuthHandler::loginUser(const Pistache::Rest::Request& req,
                            Pistache::Http::ResponseWriter response) {
    using json = nlohmann::json;

    std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
    std::shared_ptr<Redis> redis_ptr = _redisPool->getConnection();
    try {
        auto body = req.body();
        json j = json::parse(body);
        std::string stored_hash;

        std::string username = j.value("name", "");
        std::string password = j.value("password", "");

        if (username.empty() || password.empty()) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "missing username or password"})");
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (!(mysql_ptr->getUserPasswordHash(username, stored_hash))) {
            response.send(Pistache::Http::Code::Unauthorized,
                          R"({"error": "invalid credentials"})");
            _redisPool->releaseConnection(redis_ptr);
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (bcrypt_checkpw(password.c_str(), stored_hash.c_str()) == 0) {
            Session session;
            session.createSession(username);
            session.persistToRedis(redis_ptr);

            std::string sessionId = session.getSession();
            _redisPool->releaseConnection(redis_ptr);

            std::cerr << "[Login INFO] Successed login! User: " << username
                      << " session:" << sessionId << std::endl;
            _mysqlPool->releaseConnection(mysql_ptr);

            Pistache::Http::Cookie cookie("session", sessionId);
            cookie.httpOnly = true;
            cookie.secure = true;
            response.cookies().add(cookie);
            response.send(Pistache::Http::Code::Ok, R"({"message": "login successful"})");
        } else {
            _mysqlPool->releaseConnection(mysql_ptr);
            _redisPool->releaseConnection(redis_ptr);
            response.send(Pistache::Http::Code::Unauthorized,
                          R"({"error": "invalid credentials"})");
        }
    } catch (const std::exception& e) {
        response.send(Pistache::Http::Code::Bad_Request, R"({"error":"invalid json"})");
        _mysqlPool->releaseConnection(mysql_ptr);
        _redisPool->releaseConnection(redis_ptr);
    }
}

void AuthHandler::registerEmail(const Pistache::Rest::Request& req,
                                Pistache::Http::ResponseWriter response) {
    using json = nlohmann::json;

    const std::string REDIS_KEY_PREFIX = "email_verify_code:";
    std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
    std::shared_ptr<Redis> redis_ptr = _redisPool->getConnection();

    try {
        auto body = req.body();
        json j = json::parse(body);
        std::string userEmail = j.value("email", "");
        std::string name = j.value("name", "");

        if (!isValidEmail(userEmail)) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "please input valid email"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            _redisPool->releaseConnection(redis_ptr);
            return;
        }
        if (name.length() < 3 || name.length() > 20) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "name must be 3-20 characters"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        if (mysql_ptr->queryUser(name)) {
            response.send(Pistache::Http::Code::Conflict,
                          R"({"error": "name has existed"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            _redisPool->releaseConnection(redis_ptr);
            return;
        }

        if (mysql_ptr->queryEmail(userEmail)) {
            response.send(Pistache::Http::Code::Conflict,
                          R"({"error": "email has existed"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            _redisPool->releaseConnection(redis_ptr);
            return;
        }
        _mysqlPool->releaseConnection(mysql_ptr);

        std::string code = generateSixDigitCode();
        std::string key = REDIS_KEY_PREFIX + userEmail;
        redis_ptr->set(key, code, 600);

        Email email(userEmail, name, code);
        std::string sendResult = email.sendTencentSESEmail();
        _redisPool->releaseConnection(redis_ptr);

        try {
            json result = json::parse(sendResult);
            if (result.contains("Response") && result["Response"].contains("Error")) {
                response.send(Pistache::Http::Code::Internal_Server_Error,
                              R"({"error": "send verify email failed"})");
                return;
            }
        } catch (const std::exception&) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"error": "send verify email failed"})");
            return;
        }

        response.send(Pistache::Http::Code::Ok, R"({"message": "send verify succeeded"})");
    } catch (const std::exception& e) {
        MY_LOG_ERROR("registerEmail failed: ", e.what());
        response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
        _mysqlPool->releaseConnection(mysql_ptr);
        _redisPool->releaseConnection(redis_ptr);
    }
}

void AuthHandler::registerUser(const Pistache::Rest::Request& req,
                               Pistache::Http::ResponseWriter response) {
    using json = nlohmann::json;

    std::shared_ptr<Mysql> mysql_ptr;
    try {
        auto body = req.body();
        json j = json::parse(body);

        mysql_ptr = _mysqlPool->getConnection();
        std::string name = j.value("name", "");
        std::string password = j.value("password", "");
        std::string email = j.value("email", "");

        if (!isValidEmail(email)) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "please input valid email"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }
        if (name.length() < 3 || name.length() > 20) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "name must be 3-20 characters"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (mysql_ptr->queryUser(name)) {
            response.send(Pistache::Http::Code::Conflict,
                          R"({"error": "name has existed"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (mysql_ptr->queryEmail(email)) {
            response.send(Pistache::Http::Code::Conflict,
                          R"({"error": "email has existed"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        char hash[BCRYPT_HASHSIZE];
        char salt[BCRYPT_HASHSIZE] = {0};
        if (bcrypt_gensalt(12, salt)) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"error": "generate salt failed"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }
        if (isWeakPassword(password)) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "password is too weak"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }
        if (!isStrongPassword(password)) {
            response.send(Pistache::Http::Code::Bad_Request,
                          R"({"error": "password must be at least 8 characters and contain at least 3 of: lowercase, uppercase, digit, special character"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }
        if (bcrypt_hashpw(password.c_str(), salt, hash) != 0) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"error": "hash failed"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        if (!(mysql_ptr->insertUser(name, std::string(hash), email))) {
            response.send(Pistache::Http::Code::Conflict,
                          R"({"error": "name already taken or db error"})");
            _mysqlPool->releaseConnection(mysql_ptr);
            return;
        }

        std::cerr << "[Login INFO] Successed Register! User: " << name << std::endl;
        _mysqlPool->releaseConnection(mysql_ptr);
        mysql_ptr.reset();

        response.headers().add<Pistache::Http::Header::ContentType>(
            Pistache::Http::Mime::MediaType("application/json"));
        response.send(Pistache::Http::Code::Created, R"({"message": "user registered"})");

    } catch (const std::exception& e) {
        response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
        if (mysql_ptr) {
            _mysqlPool->releaseConnection(mysql_ptr);
        }
    }
}
