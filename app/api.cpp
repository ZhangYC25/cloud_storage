#include "api.h"

Api::Api(){ _mysqlPool = MySQLConnPool::getInstance();}

//合理吗？之后再说
//Api::~Api() { _conPool = nullptr;}

void Api::setupRoutes(){
	// 方式1：结合std::bind（推荐，兼容性好）
	using namespace Pistache::Rest;
    using Pistache::Http::ResponseWriter;
    // 使用 [this] 捕获当前对象，并确保 Lambda 签名与 Pistache::Rest::Route::Handler 匹配
    Routes::Post(router, "/api/register", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            // 在 Lambda 内部调用成员函数
            this->registerUser(req, std::move(response));
            return Route::Result::Ok; // 返回必须的结果类型
        }
    );

    Routes::Post(router, "/api/login", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            this->loginUser(req, std::move(response));
            return Route::Result::Ok;
        }
    );
    
    Routes::Post(router, "/api/upload/file", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            this->upload(req, std::move(response));
            return Route::Result::Ok;
        }
    );
    
    Routes::Post(router, "/api/upload/check", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            this->uploadCheck(req, std::move(response));
            return Route::Result::Ok;
        }
    );
}


void Api::loginUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
    try {
		auto body = req.body();
		json j = json::parse(body);
        std::shared_ptr<Mysql> connPtr = _mysqlPool->getConnection();
        
		std::string username = j.value("name", "");
		//std::string nickname = j.value("nickname", "");
		std::string password = j.value("password", "");

		if (username.empty() || password.empty()) {
           		response.send(Pistache::Http::Code::Bad_Request, R"({"error": "missing username or password"})");
            		return;
        	}

        	std::string stored_hash;
        	if (!(connPtr -> getUserPasswordHash(username, stored_hash))) {
            		response.send(Pistache::Http::Code::Unauthorized, R"({"error": "invalid credentials"})");
            		return;
        	}
			_mysqlPool -> releaseConnection(connPtr);
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

// ========= POST /login =========
void Api::registerUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	try{
		auto body = req.body();
		json j = json::parse(body);

		std::shared_ptr<Mysql> connPtr = _mysqlPool->getConnection();

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

		if (!(connPtr->insertUser(name, std::string(hash)))) {
			response.send(Pistache::Http::Code::Conflict, R"({"error": "name already taken or db error"})");
			return;
		}

		_mysqlPool->releaseConnection(connPtr);

		response.headers().add<Pistache::Http::Header::ContentType>(
			Pistache::Http::Mime::MediaType("application/json"));
		response.send(Pistache::Http::Code::Created, R"({"message": "user registered"})");

	} catch (const std::exception& e) {
		response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
	}
}

// =========== POST / up and check
void Api::uploadCheck(const  Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	try{
		auto body = req.body(); //filename md5 filesize;
		json j = json::parse(body);
		std::shared_ptr connPtr = _mysqlPool -> getConnection();
		std::string filename = j.value("filename","");
		std::string md5 = j.value("md5","");
		std::string user = j.value("name","");

		if (connPtr->isInMySQL(md5)) {
			// in MySQL and in UserList
			if (connPtr->isInUserList(md5, user)) {
				response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
                return;
			} else { // in MySQL but Not in UserList
				// 秒传：插入关系 + 引用计数+1
                if (connPtr->insertUserFile(md5, user, filename)) {
					response.send(Pistache::Http::Code::Ok,
						R"({"success":true,"status":"instant_upload"})",
						MIME(Application, Json));
					return;
				}
			}
		}

		// 3. 系统也没有 → 需要上传，缓存 MD5 到 Redis
    	//redisContext* redis_ctx = (new(Redis))->getRedisContext();
		Redis* redis = new Redis();
		redisReply* redis_reply = nullptr;

		/************************ 3. 执行SETEX缓存MD5相关信息 ************************/
    // 优化后的Redis Key：以MD5为核心，避免文件名重复覆盖
    	std::string redis_key = md5;
    // 缓存值：可扩展为JSON存储更多信息（如文件大小、分块数）
    	std::string redis_value = filename;

    // 执行SETEX命令（设置键值+过期时间）
    	redis_reply = (redisReply*)redisCommand(redis->getRedisContext(), "SETEX %s %d %s",
        	redis_key.c_str(), 3600, redis_value.c_str());
    	if (redis_reply == nullptr) {
        	std::cerr << "Redis SETEX命令执行失败: " << redis->getRedisContext()->errstr << std::endl;
        	//redisFree(redis_ctx);
			delete redis;
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
        	//redisFree(redis_ctx);
			delete redis;
        	response.send(Pistache::Http::Code::Internal_Server_Error,
            	R"({"success":false,"message":"Redis缓存设置失败"})",
            	MIME(Application, Json));
        	return;
    	}

    /************************ 4. 释放Redis资源 ************************/
    	freeReplyObject(redis_reply);  // 释放SETEX响应
    	//redisFree(redis_ctx);          
		// 关闭Redis连接
		delete redis;

		_mysqlPool->releaseConnection(connPtr);
    /************************ 5. 返回业务响应 ************************/
    	response.send(Pistache::Http::Code::Ok,
        	R"({"success":true,"status":"need_upload"})",
        	MIME(Application, Json));

		} catch (const std::exception& e) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
		}
}

// ================= POST / upload 
void Api::upload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){

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
        //redisContext* redis_ctx = redisConnect(redis_host.c_str(), REDIS_PORT);
		Redis* redis = new Redis();
        redisReply* md5_reply = (redisReply*)redisCommand(redis->getRedisContext(), "GET %s", md5.c_str());
        if (!md5_reply || md5_reply->type == REDIS_REPLY_NIL) {
            freeReplyObject(md5_reply);
            //redisFree(redis_ctx);
			delete redis;
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"请先调用 /upload/check"})",
                MIME(Application, Json));
            return;
        }
        freeReplyObject(md5_reply);

		// upload to Fastdfs
		//write to tmp file /tmp/fastdfs_upload_XXXXXX
		std::shared_ptr fdfs_ptr = FdfsConnPool::getInstance()->getConnection();
		std::string temp_path = fdfs_ptr -> create_temp_file(fileData);
		if (temp_path.empty()) {
           response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"/write /tmp/ false"})",
                MIME(Application, Json));
            return;
        }

		//upload
		std::string fastdfs_path = fdfs_ptr -> upload_file_to_fastdfs(temp_path.c_str());
		//std::string fastdfs_path = upload_file_to_fastdfs(temp_path.c_str());
		if (fastdfs_path.empty()) {
           	response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"upload to fastdfs false"})",
                MIME(Application, Json));
            return;
        }
		//delete tem file
		std::filesystem::remove(temp_path);
		
		std::shared_ptr connPtr = _mysqlPool -> getConnection();
		//入数据库
		connPtr -> insertUserFile(md5, user, filename);
		connPtr -> insertFileInfo(md5, fastdfs_path);
		_mysqlPool -> releaseConnection(connPtr);

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

