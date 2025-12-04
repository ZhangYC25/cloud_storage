#include <pistache/endpoint.h>
#include <pistache/router.h>
#include <pistache/http.h>

#include <stdlib.h>
#include <mysql/mysql.h>
#include <redis/hiredis.h>
#include <bcrypt.h>
#include <nlohmann/json.hpp>
#include<iostream>
#include <string>
#include <csignal>
#include <memory>
#include <chrono>
#include <iomanip>
#include <sstream>
extern "C" {
    #include "fastdfs/fdfs_client.h"
    #include "fastcommon/logger.h"
}

//
#define DB_PORT 3306
#define REDIS_PORT 6379

using json = nlohmann::json;

// sign handle
std::shared_ptr<Pistache::Http::Endpoint> g_server;

void handleSignal(int sig){
	if (sig == SIGINT && g_server) {
		std::cout << "\n Shutting down server..." << std::endl;
		g_server -> shutdown();
		exit(0);
	}
}


//database conf
const std::string mysql_host = "127.0.0.1";
const std::string mysql_user = "zhangyc";
const std::string mysql_pass = "zhangyc@APEX!!!";
const std::string mysql_db = "cloud_storage";

const std::string redis_host = "127.0.0.1";
const std::string redis_pass = "ZYCzyc520@APEX!";
const int redis_timeout = 5000;


//safety injection
bool insertUser(const std::string& username, const std::string& password_hash){
	MYSQL* conn = mysql_init(nullptr);
	if (!mysql_real_connect(conn, mysql_host.c_str(), mysql_user.c_str(),
	     mysql_pass.c_str(), mysql_db.c_str(), DB_PORT, nullptr, 0)) {
		std::cerr << "DB connect error: " << mysql_error(conn) << std::endl;
		mysql_close(conn);
		return false;
	}

	const char* query = "INSERT INTO user (name, nickname, password, phone, email, createtime) VALUE (?, ?, ?, NULL, NULL, ?)";
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt || mysql_stmt_prepare(stmt, query, strlen(query))) {
		std::cerr << "Prepare failed" << std::endl;
		if (stmt) mysql_stmt_close(stmt);
		mysql_close(conn);
		return false;
	}

	//create current time
	auto now = std::chrono::system_clock::now();
	auto timet = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&timet), "%Y-%m-%d %H:%M:%S");
	std::string timestamp = ss.str();

	//bind sql characteriaze
	MYSQL_BIND bind[4] = {};

	//name
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = const_cast<char*>(username.c_str());
	bind[0].buffer_length = username.length();

	//nickname = name
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = const_cast<char*>(username.c_str());
	bind[1].buffer_length = username.length();
	
	//password
	bind[2].buffer_type = MYSQL_TYPE_STRING;
	bind[2].buffer = const_cast<char*>(password_hash.c_str());
	bind[2].buffer_length = password_hash.length();
	
	//createtimr
	bind[3].buffer_type = MYSQL_TYPE_STRING;
	bind[3].buffer = const_cast<char*>(timestamp.c_str());
	bind[3].buffer_length = timestamp.length();

	//if success return 0
	if (mysql_stmt_bind_param(stmt, bind)) {
		std::cerr << "Bind param failed: " << mysql_stmt_error(stmt) << std::endl;
		mysql_stmt_close(stmt);
		mysql_close(conn);
		return false;
	}

	// if success return 0;
	bool success = !mysql_stmt_execute(stmt);
	mysql_stmt_close(stmt);
	mysql_close(conn);
	return success;
}


bool getUserPasswordHash(const std::string& username, std::string& out_hash){
	MYSQL* conn = mysql_init(nullptr);
	if (!mysql_real_connect(conn, mysql_host.c_str(), mysql_user.c_str(),
	   mysql_pass.c_str(), mysql_db.c_str(),DB_PORT, nullptr, 0)) {
		std::cerr << "DB connect error: " << mysql_error(conn) << std::endl;
		mysql_close(conn);
		return false;
	}

	const char* query = "SELECT password FROM user WHERE name = ?";
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt || mysql_stmt_prepare(stmt, query, strlen(query))) {
		std::cerr << "Prepare failed" << std::endl;
		if (stmt) mysql_stmt_close(stmt);
        	mysql_close(conn);
        	return false;
	}

	
	MYSQL_BIND bind[1] = {};
	
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = const_cast<char*>(username.c_str());
	bind[0].buffer_length = username.length();


	if (mysql_stmt_bind_param(stmt, bind)) {
		std::cerr << "Bind param failed" << std::endl;
       		mysql_stmt_close(stmt);
        	mysql_close(conn);
        	return false;
	}

	if (mysql_stmt_execute(stmt)) {
		std::cerr << "Execute error: " << std::endl;
		mysql_stmt_close(stmt);
		mysql_close(conn);
		return false;
	}

	MYSQL_BIND result_bind[1] = {};
	char hash_buffer[256];
	unsigned long hash_len = sizeof(hash_buffer);
	bool is_null = 0;

	result_bind[0].buffer_type = MYSQL_TYPE_STRING;
	result_bind[0].buffer = hash_buffer;	
	result_bind[0].buffer_length = hash_len;
	result_bind[0].length = &hash_len;
	result_bind[0].is_null = &is_null;

	//bind result || store result || fetch result
	if (mysql_stmt_bind_result(stmt, result_bind) ||
		mysql_stmt_store_result(stmt) ||
        	mysql_stmt_fetch(stmt)) {
        	mysql_stmt_close(stmt);
        	mysql_close(conn);
        	return false;
	}

	out_hash = std::string(hash_buffer, hash_len);
	mysql_stmt_close(stmt);
	mysql_close(conn);
	return true;
}


//============ POST /register ============
void registerUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	try{
		auto body = req.body();
		json j = json::parse(body);

		std::string name = j.value("name","");
		std::string password = j.value("password","");
		
		if (name.empty() || password.empty()) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "name and password are required"})");
			return;
		}

		//check name
		if (name.length() < 3 || name.length() > 128) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "name must be 3-128 characters"})");
			return;
		}

		//char hash[BCRYPT_HASHSIZE];
		//if (bcrypt_hashpw(password.c_str(), bcrypt_gensalt(12), hash) != 0) {
			//response.send(Pistache::Http::Code::Internal_Server_Error, R"({"error": "hash failed"})");
			//return;
		//}
		char hash[BCRYPT_HASHSIZE];
		char salt[BCRYPT_HASHSIZE] = {0}; // 盐值缓冲区
		if (bcrypt_gensalt(12, salt)) { // 先生成盐值
    			response.send(Pistache::Http::Code::Internal_Server_Error, R"({"error": "generate salt failed"})");
    			return;
			}
		if (bcrypt_hashpw(password.c_str(), salt, hash) != 0) { 
			// 用生成的盐值计算哈希
    			response.send(Pistache::Http::Code::Internal_Server_Error, R"({"error": "hash failed"})");
    			return;
		}

		if (!insertUser(name, std::string(hash))) {
			response.send(Pistache::Http::Code::Conflict, R"({"error": "name already taken or db error"})");
			return;
		}

		response.headers().add<Pistache::Http::Header::ContentType>(
			Pistache::Http::Mime::MediaType("application/json"));
		response.send(Pistache::Http::Code::Created, R"({"message": "user registered"})");

	} catch (const std::exception& e) {
		response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
	}
}

// ========= POST /login =========
void loginUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	try {
		auto body = req.body();
		json j = json::parse(body);

		std::string username = j.value("name", "");
		//std::string nickname = j.value("nickname", "");
		std::string password = j.value("password", "");

		if (username.empty() || password.empty()) {
           		response.send(Pistache::Http::Code::Bad_Request, R"({"error": "missing username or password"})");
            		return;
        	}

        	std::string stored_hash;
        	if (!getUserPasswordHash(username, stored_hash)) {
            		response.send(Pistache::Http::Code::Unauthorized, R"({"error": "invalid credentials"})");
            		return;
        	}

		if (bcrypt_checkpw(password.c_str(), stored_hash.c_str()) == 0) {
            		response.headers().add<Pistache::Http::Header::ContentType>(Pistache::Http::Mime::MediaType("application/json"));
            		response.send(Pistache::Http::Code::Ok, R"({"message": "login successful"})");
        	} else {
            		response.send(Pistache::Http::Code::Unauthorized, R"({"error": "invalid credentials"})");
        	}
	} catch (const std::exception& e) {
		response.send(Pistache::Http::Code::Bad_Request, R"({"error":"invalid json"})");
	}
}


// ================= POST /api/upload/check ==================

//======== is in MySQL ? ==========
bool isInMySQL(const std::string& md5){
	// 初始化MySQL连接句柄
    MYSQL* conn = mysql_init(nullptr);
    if (conn == nullptr) {
        std::cerr << "mysql_init failed" << std::endl;
        return false;
    }

    // 连接数据库
    if (!mysql_real_connect(conn, mysql_host.c_str(), mysql_user.c_str(),
                            mysql_pass.c_str(), mysql_db.c_str(), DB_PORT, nullptr, 0)) {
        std::cerr << "isInDB connect error: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return false;
    }

    // 构造查询SQL（注意：生产环境建议用预处理语句防SQL注入）
    std::string query = "SELECT 1 FROM file_info WHERE md5 = '" + md5 + "'";

    // 执行SQL语句，用int接收执行结果
    int query_ret = mysql_query(conn, query.c_str());
    bool exists = false; // 变量名修正：exits -> exists（笔误）

    if (query_ret != 0) {
        std::cerr << "Query error: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return exists;
    }

    // 关键：获取查询结果集（MYSQL_RES*类型）
    MYSQL_RES* res = mysql_store_result(conn);
    if (res == nullptr) {
        std::cerr << "mysql_store_result error: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return exists;
    }

    // 从结果集中获取行数据
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row != nullptr) {
        exists = true; // 查到数据则标记为存在
    }

    // 释放结果集资源（必须调用，避免内存泄漏）
    mysql_free_result(res);
    // 关闭数据库连接
    mysql_close(conn);

    return exists;
}

//========== is in user list ===========
bool isInUserList(const std::string& md5, const std::string& username){
	MYSQL* conn = mysql_init(nullptr);
	if (!mysql_real_connect(conn, mysql_host.c_str(), mysql_user.c_str(),
	   mysql_pass.c_str(), mysql_db.c_str(),DB_PORT, nullptr, 0)) {
		std::cerr << "isInUserList connect error: " << mysql_error(conn) << std::endl;
		mysql_close(conn);
		return false;
	}

	std::string query = "SELECT 1 FROM user_file_list WHERE md5 = '" + md5 + "' and user = '" + username + "'";
	
	int query_ret = mysql_query(conn, query.c_str());
    if (query_ret != 0) { // 非0表示查询失败
        std::cerr << "isInUserList Query error: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return false;
    }

    MYSQL_RES* res = mysql_store_result(conn);
    if (res == nullptr) {
        std::cerr << "mysql_store_result failed: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return false;
    }

    bool exists = false;
    // 6. 读取行：若有行则表示记录存在
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row != nullptr) {
        exists = true;
    }

    mysql_free_result(res);
    mysql_close(conn);

    return exists;
}

//========= insertUserFile =============
bool insertUserFile(const std::string& md5, const std::string& username, const std::string& filename){
	MYSQL* conn = nullptr;
    int ret = 0;
    bool result = false;

    // 1. 初始化MySQL连接对象
    conn = mysql_init(nullptr);
    if (conn == nullptr) {
        std::cerr << "mysql_init failed: 初始化连接对象失败" << std::endl;
        return false;
    }

    // 2. 建立数据库连接
    if (!mysql_real_connect(conn, mysql_host.c_str(), mysql_user.c_str(),
	   mysql_pass.c_str(), mysql_db.c_str(),DB_PORT, nullptr, 0)) {
		std::cerr << "isInUserList connect error: " << mysql_error(conn) << std::endl;
		mysql_close(conn);
		return false;
	}

    try {
        // 3. 开启事务（保证插入和更新操作的原子性）
        ret = mysql_query(conn, "START TRANSACTION");
        if (ret != 0) {
            throw std::runtime_error("开启事务失败: " + std::string(mysql_error(conn)));
        }

        // 4. 向user_file_list表插入记录
        // 拼接SQL（注意：生产环境必须用预处理语句防注入，此处先按需求实现基础功能）
        std::string insertUserSql = "INSERT INTO user_file_list (md5, user, filename, createtime) "
                                    "VALUES ('" + md5 + "', '" + username + "', '" + filename + "', NOW())";
        ret = mysql_query(conn, insertUserSql.c_str());
        if (ret != 0) {
            throw std::runtime_error("插入user_file_list失败: " + std::string(mysql_error(conn)));
        }
        std::cout << "成功向user_file_list插入记录,md5: " << md5 << ", 用户名: " << username << std::endl;

        // 5. 更新file_info表的count字段（存在则+1，不存在则初始化count=1）
        // 使用INSERT ... ON DUPLICATE KEY UPDATE实现「存在更新，不存在插入」
        //std::string updateFileInfoSql = "INSERT INTO file_info (md5, count) "
                                        //"VALUES ('" + md5 + "', 1) "
                                        //"ON DUPLICATE KEY UPDATE count = count + 1";
        //ret = mysql_query(conn, updateFileInfoSql.c_str());
        //if (ret != 0) {
            //throw std::runtime_error("更新file_info count失败: " + std::string(mysql_error(conn)));
        //}
        //std::cout << "成功更新file_info表,md5: " << md5 << "的count字段+1" << std::endl;

        // 6. 提交事务
        ret = mysql_query(conn, "COMMIT");
        if (ret != 0) {
            throw std::runtime_error("提交事务失败: " + std::string(mysql_error(conn)));
        }
        result = true; // 所有操作成功

    } catch (const std::runtime_error& e) {
        // 7. 出错时回滚事务
        std::cerr << "操作失败，回滚事务: " << e.what() << std::endl;
        mysql_query(conn, "ROLLBACK");
        result = false;
    }

    // 8. 释放数据库资源
    mysql_close(conn);
    return result;
}

//============= insert file_info ==============

bool insertFileInfo(const std::string& md5, const std::string& url){
	MYSQL* conn = nullptr;
    int ret = 0;
    bool result = false;

    // 1. 初始化MySQL连接对象
    conn = mysql_init(nullptr);
    if (conn == nullptr) {
        std::cerr << "mysql_init failed: 初始化连接对象失败" << std::endl;
        return false;
    }

    // 2. 建立数据库连接
    if (!mysql_real_connect(conn, mysql_host.c_str(), mysql_user.c_str(),
	   mysql_pass.c_str(), mysql_db.c_str(),DB_PORT, nullptr, 0)) {
		std::cerr << "isInUserList connect error: " << mysql_error(conn) << std::endl;
		mysql_close(conn);
		return false;
	}

    try {
        // 3. 开启事务（保证插入和更新操作的原子性）
        ret = mysql_query(conn, "START TRANSACTION");
        if (ret != 0) {
            throw std::runtime_error("开启事务失败: " + std::string(mysql_error(conn)));
        }

        // 4. 更新file_info表 (存在则+1，不存在则初始化count=1）
        // 使用INSERT ... ON DUPLICATE KEY UPDATE实现「存在更新，不存在插入」
        std::string updateFileInfoSql = "INSERT INTO file_info (md5, url, count) "
                                        "VALUES ('" + md5 + "','" + url + "', 1) "
                                        "ON DUPLICATE KEY UPDATE count = count + 1";
        ret = mysql_query(conn, updateFileInfoSql.c_str());
        if (ret != 0) {
            throw std::runtime_error("更新file_info count失败: " + std::string(mysql_error(conn)));
        }
        std::cout << "成功更新file_info表,md5: " << md5 << "的count字段+1" << std::endl;

        // 6. 提交事务
        ret = mysql_query(conn, "COMMIT");
        if (ret != 0) {
            throw std::runtime_error("提交事务失败: " + std::string(mysql_error(conn)));
        }
        result = true; // 所有操作成功

    } catch (const std::runtime_error& e) {
        // 7. 出错时回滚事务
        std::cerr << "操作失败，回滚事务: " << e.what() << std::endl;
        mysql_query(conn, "ROLLBACK");
        result = false;
    }

    // 8. 释放数据库资源
    mysql_close(conn);
    return result;

}

void uploadCheck(const  Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	try{
		auto body = req.body(); //filename md5 filesize;
		json j = json::parse(body);

		std::string filename = j.value("filename","");
		std::string md5 = j.value("md5","");
		std::string user = j.value("name","");

		if (isInMySQL(md5)) {
			// in MySQL and in UserList
			if (isInUserList(md5, user)) {
				response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
                return;
			} else { // in MySQL but Not in UserList
				// 秒传：插入关系 + 引用计数+1
                if ( true == insertUserFile(md5, user, filename)) {
					response.send(Pistache::Http::Code::Ok,
						R"({"success":true,"status":"instant_upload"})",
						MIME(Application, Json));
					return;
				}
			}
		}

		// 3. 系统也没有 → 需要上传，缓存 MD5 到 Redis
		redisContext* redis_ctx = redisConnect(redis_host.c_str(), REDIS_PORT);
    	redisReply* redis_reply = nullptr;

		// 检查Redis连接是否失败
		if (redis_ctx == nullptr || redis_ctx->err) {
			std::cerr << "Redis连接失败: " << (redis_ctx ? redis_ctx->errstr : "内存分配错误") << std::endl;
			// 释放连接（若存在）
			if (redis_ctx) redisFree(redis_ctx);
			// 返回服务端错误响应
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"Redis连接失败"})",
				MIME(Application, Json));
			return;
		}
	
		/************************ 2. 执行Redis AUTH密码认证 ************************/
		std::cerr << "【DEBUG】正在使用的 Redis 密码: [" << redis_pass << "]" << std::endl;

		// 1. 定义命令和参数
		const char *argv[] = {"AUTH", redis_pass.c_str()};
		size_t argvlen[] = {4, redis_pass.length()}; // 4是"AUTH"的长度

		// 2. 使用 redisCommandArgv 发送命令
		// 传入参数：上下文，参数数量 (2: "AUTH" 和 密码)，参数数组，参数长度数组
		redis_reply = (redisReply*)redisCommandArgv(redis_ctx, 2, argv, argvlen);
		//redis_reply = (redisReply*)redisCommand(redis_ctx, "AUTH %s", redis_pass);
		std::cerr << redis_reply -> str << std::endl;
		std::cerr << redis_reply->type << std::endl;
		if (redis_reply == nullptr) {
			std::cerr << "Redis认证命令发送失败: " << redis_ctx->errstr << std::endl;
			redisFree(redis_ctx);
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"Redis认证失败"})",
				MIME(Application, Json));
			return;
		}
	
		// 校验认证结果：成功返回"OK"，失败返回错误信息
		if (!(redis_reply->type == REDIS_REPLY_STATUS && strcasecmp(redis_reply->str, "OK") == 0)) {
			std::cerr << "Redis密码认证失败: " << (redis_reply->str ? redis_reply->str : "未知错误") << std::endl;
			freeReplyObject(redis_reply);  // 释放认证响应
			redisFree(redis_ctx);
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"Redis密码错误或认证失败"})",
				MIME(Application, Json));
			return;
		}
		std::cout << "Redis密码认证成功" << std::endl;
		freeReplyObject(redis_reply);  // 释放认证响应（必须释放，避免内存泄漏）


		/************************ 3. 执行SETEX缓存MD5相关信息 ************************/
    // 优化后的Redis Key：以MD5为核心，避免文件名重复覆盖
    	std::string redis_key = md5;
    // 缓存值：可扩展为JSON存储更多信息（如文件大小、分块数）
    	std::string redis_value = filename;

    // 执行SETEX命令（设置键值+过期时间）
    	redis_reply = (redisReply*)redisCommand(redis_ctx, "SETEX %s %d %s",
        	redis_key.c_str(), 3600, redis_value.c_str());
    	if (redis_reply == nullptr) {
        	std::cerr << "Redis SETEX命令执行失败: " << redis_ctx->errstr << std::endl;
        	redisFree(redis_ctx);
        	response.send(Pistache::Http::Code::Internal_Server_Error,
            	R"({"success":false,"message":"Redis缓存失败"})",
            	MIME(Application, Json));
        	return;
    	}

    // 校验SETEX执行结果
    	if (redis_reply->type == REDIS_REPLY_STATUS && strcasecmp(redis_reply->str, "OK") == 0) {
        	std::cout << "Redis缓存成功, Key: " << redis_key << ", Value: " << redis_value << std::endl;
    	} else {
        	std::cerr << "Redis SETEX执行失败: " << (redis_reply->str ? redis_reply->str : "未知响应") << std::endl;
        	freeReplyObject(redis_reply);
        	redisFree(redis_ctx);
        	response.send(Pistache::Http::Code::Internal_Server_Error,
            	R"({"success":false,"message":"Redis缓存设置失败"})",
            	MIME(Application, Json));
        	return;
    	}

    /************************ 4. 释放Redis资源 ************************/
    	freeReplyObject(redis_reply);  // 释放SETEX响应
    	redisFree(redis_ctx);          // 关闭Redis连接

    /************************ 5. 返回业务响应 ************************/
    	response.send(Pistache::Http::Code::Ok,
        	R"({"success":true,"status":"need_upload"})",
        	MIME(Application, Json));

		} catch (const std::exception& e) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
		}
}

std::string upload_file_to_fastdfs(const char* local_path){
	const char* conf_path = "/etc/fdfs/client.conf";
	if (fdfs_client_init(conf_path) != 0) {
		return "";
	}

	ConnectionInfo* pTrackerServer = tracker_get_connection();
	if (!pTrackerServer) {
		fdfs_client_destroy();
		return "";
	}

	ConnectionInfo storageServer;
	memset(&storageServer, 0, sizeof(storageServer));
	char group_name[FDFS_GROUP_NAME_MAX_LEN + 1] = {0};
	int store_path_index = 0;

	int result = tracker_query_storage_store(pTrackerServer, &storageServer,
			group_name, &store_path_index);
	if (result != 0) {
		tracker_close_connection_ex(pTrackerServer,true);
		fdfs_client_destroy();
		return "";
	}

	char file_id[256] = {0};
	//提取文件扩展名
	const char* ext = strrchr(local_path,'.');
	const char* file_ext = ext?ext+1:"";

	result = storage_upload_by_filename(
        pTrackerServer,
        &storageServer,
        store_path_index,
        local_path,
        file_ext,
        nullptr, 0,
        group_name,
        file_id
    );

	tracker_close_connection_ex(pTrackerServer, true);
    fdfs_client_destroy();

    if (result == 0) {
        return std::string(group_name) + "/" + std::string(file_id);
    }
    return "";
}

// 工具：生成唯一临时文件名
std::string create_temp_file(const std::vector<char>& data) {
    char temp_template[] = "/tmp/fastdfs_upload_XXXXXX";
    int fd = mkstemp(temp_template);
    if (fd == -1) return "";
    
    ssize_t written = write(fd, data.data(), data.size());
	
	if (written != static_cast<ssize_t>(data.size())) {
    	close(fd);
    	unlink(temp_template); // 删除创建的临时文件
    	return "";
	}
    close(fd);
    return std::string(temp_template);
}


void upload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	try {
		auto contentType = req.headers().tryGet<Pistache::Http::Header::ContentType>();
        if (!contentType) {
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"需要 multipart/form-data"})",
                MIME(Application, Json));
            return;
        }

        std::string ct = contentType->mime().toString();

        // 找 boundary
        std::string boundary;
        {
            auto pos = ct.find("boundary=");
            if (pos == std::string::npos) {
                response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"未找到 boundary"})",
                    MIME(Application, Json));
                return;
            }
            boundary = "--" + ct.substr(pos + 9);  // 添加前缀 --
        }

        const std::string& body = req.body();

        std::string filename, md5, user;
        std::vector<char> fileData;

        size_t pos = 0;
        while (true) {
            size_t start = body.find(boundary, pos);
            if (start == std::string::npos) break;
            start += boundary.size() + 2; // skip CRLF

            size_t headerEnd = body.find("\r\n\r\n", start);
            if (headerEnd == std::string::npos) break;

            std::string header = body.substr(start, headerEnd - start);
            size_t contentStart = headerEnd + 4;

            // 找下一段
            size_t nextBoundary = body.find(boundary, contentStart);
            if (nextBoundary == std::string::npos) break;

            size_t contentEnd = nextBoundary - 2; // remove \r\n

            std::string content = body.substr(contentStart, contentEnd - contentStart);

            // 解析 header
            if (header.find("name=\"file\"") != std::string::npos) {
                // 文件名
                auto fnPos = header.find("filename=\"");
                if (fnPos != std::string::npos) {
                    fnPos += 10;
                    size_t fnEnd = header.find("\"", fnPos);
                    filename = header.substr(fnPos, fnEnd - fnPos);
                }
                fileData.assign(content.begin(), content.end());
            }
            else if (header.find("name=\"filename\"") != std::string::npos) {
                filename = content;
            }
            else if (header.find("name=\"md5\"") != std::string::npos) {
                md5 = content;
            }
            else if (header.find("name=\"user\"") != std::string::npos) {
                user = content;
            }

            pos = nextBoundary;
        }

        if (fileData.empty()) {
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"文件为空"})",
                MIME(Application, Json));
            return;
        }

		// 校验 Redis：确保前端 upload/check 已设置 md5
        redisContext* redis_ctx = redisConnect(redis_host.c_str(), REDIS_PORT);
        if (!redis_ctx || redis_ctx->err) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                R"({"success":false,"message":"Redis连接失败"})",
                MIME(Application, Json));
            return;
        }

		const char *argv[] = {"AUTH", redis_pass.c_str()};
		size_t argvlen[] = {4, redis_pass.length()}; // 4是"AUTH"的长度

		// 2. 使用 redisCommandArgv 发送命令
		// 传入参数：上下文，参数数量 (2: "AUTH" 和 密码)，参数数组，参数长度数组
		redisReply* auth_reply = (redisReply*)redisCommandArgv(redis_ctx, 2, argv, argvlen);
        //redisReply* auth_reply = (redisReply*)redisCommand(redis_ctx, "AUTH %s", redis_pass);
        if (!auth_reply || strcasecmp(auth_reply->str, "OK") != 0) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                R"({"success":false,"message":"Redis认证失败"})",
                MIME(Application, Json));
            return;
        }
        freeReplyObject(auth_reply);


        redisReply* md5_reply = (redisReply*)redisCommand(redis_ctx, "GET %s", md5.c_str());
        if (!md5_reply || md5_reply->type == REDIS_REPLY_NIL) {
            freeReplyObject(md5_reply);
            redisFree(redis_ctx);

            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"请先调用 /upload/check"})",
                MIME(Application, Json));
            return;
        }
        freeReplyObject(md5_reply);

		// upload to Fastdfs
		//write to tmp file /tmp/fastdfs_upload_XXXXXX
		std::string temp_path = create_temp_file(fileData);
		if (temp_path.empty()) {
           response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"/write /tmp/ false"})",
                MIME(Application, Json));
            return;
        }

		//upload
		std::string fastdfs_path = upload_file_to_fastdfs(temp_path.c_str());
		if (fastdfs_path.empty()) {
           	response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"upload to fastdfs false"})",
                MIME(Application, Json));
            return;
        }
		//delete tem file
		std::filesystem::remove(temp_path);

		//入数据库
		insertUserFile(md5, user, filename);
		insertFileInfo(md5, fastdfs_path);
		

		// 构造 JSON 对象
		json responseJson = {
    		{"success", true},
    		{"message", "file uploaded successfully"},
    		{"url", "http://146.56.194.96/" + fastdfs_path},
    		{"fastdfs_path", fastdfs_path}
		};

		response.send(
    		Pistache::Http::Code::Ok,
    		responseJson.dump(), // 转成 std::string
    		MIME(Application, Json)
		);

	} catch (...) {
		response.send(Pistache::Http::Code::Internal_Server_Error,
            R"({"success":false,"message":"服务器异常"})",
            MIME(Application, Json));
	}
}



//============== set route =============
void setupRoutes(Pistache::Rest::Router& router){
	Pistache::Rest::Routes::Post(router, "/api/register", Pistache::Rest::Routes::bind(&registerUser));
	Pistache::Rest::Routes::Post(router, "/api/login", Pistache::Rest::Routes::bind(&loginUser));
	Pistache::Rest::Routes::Post(router, "/api/upload/file", Pistache::Rest::Routes::bind(&upload));
	Pistache::Rest::Routes::Post(router, "/api/upload/check", Pistache::Rest::Routes::bind(&uploadCheck));
}

int main(){
	//Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(2048));
	Pistache::Address addr(Pistache::Address("127.0.0.1", Pistache::Port(2048)));
	auto server = std::make_shared<Pistache::Http::Endpoint>(addr);
	
	g_server = server;
	signal(SIGINT, handleSignal);
	auto opts = Pistache::Http::Endpoint::options().threads(4).maxRequestSize(1204 * 64);

	try {
		server -> init(opts);
	} catch (std::exception& e) {
		std::cerr << "Server init failed: " << e.what() << std::endl;
		return -1;
	}

	Pistache::Rest::Router router;
	setupRoutes(router);
	server -> setHandler(router.handler());
	server -> serve();
	return 0;

}
