#include "api.h"
#include "session.h"


std::shared_ptr<Api> Api::_apiInstance = nullptr;

std::shared_ptr<Api> Api::getInstance(){
	if (_apiInstance == nullptr) {
		static std::mutex instanceMutex;
		std::lock_guard<std::mutex> lock(instanceMutex);
		if (_apiInstance == nullptr) {
                std::shared_ptr<Api> instance(new Api());
				_apiInstance = instance;
            }
	}
	return _apiInstance;
}

Api::Api(){ 
	_mysqlPool = MySQLConnPool::getInstance();
	_fdfsPool = FdfsConnPool::getInstance();
	_redisPool = RedisConnPool::getInstance();
}

//合理吗？之后再说
Api::~Api() {}
// ============================= Session ================================



// ============================= API ===================================
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

	Routes::Get(router, "/api/files", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            this->queryUserFiles(req, std::move(response));
            return Route::Result::Ok;
        }
    );

	Routes::Delete(router, "/api/delete", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            this->deleteCheck(req, std::move(response));
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
		if (bcrypt_checkpw(password.c_str(), stored_hash.c_str()) == 0) {
					
			std::shared_ptr<Session> session_ptr = std::make_shared<Session>();
			session_ptr -> createSession(username);
			auto it = _sessions.find(username);
			if (it == _sessions.end()){
				//说明用户第一次登录 或者 上传登录已经过期
				std::cerr<<"[Session INFO] _session size: "<<_sessions.size()<<std::endl;
				_sessions[username] = session_ptr;
				std::cerr<<"[Session INFO] _session size: "<<_sessions.size()<<std::endl;
			} else { //找到了，说明上传登录的信息还残留
				std::cerr<<"[Session INFO] _session size: "<<_sessions.size()<<std::endl;
				_sessions.erase(it);
				std::cerr<<"[Session INFO] _session size: "<<_sessions.size()<<std::endl;
				_sessions[username] = session_ptr;
				std::cerr<<"[Session INFO] _session size: "<<_sessions.size()<<std::endl;
				std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
				// 更新redis里面的数据 这里可以先不搞，把TTL设置小一点也行,10分钟不活跃的自动删除

				_redisPool -> releaseConnection(redis_ptr);
			}

			//只要是登录就加入redis
			std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
			// 添加到redis <sessionId, username>
			redis_ptr -> set(session_ptr->getSession(), username, 600);
			_redisPool -> releaseConnection(redis_ptr);

			std::string sessionId = session_ptr->getSession();
			std::string cookieValue = "SessionID=" + sessionId +
									"; Path=/" +
									"; HttpOnly" +
									"; Max-Age=" + std::to_string(SESSION_TIMEOUT_SECONDS) +
									"; SameSite=Strict";

			//正确添加 Set-Cookie 头
			response.headers().addRaw(Pistache::Http::Header::Raw("Set-Cookie", cookieValue));


			std::cerr<<"[Login INFO] Successed login! User: "<<username<<std::endl;
			_mysqlPool -> releaseConnection(connPtr);

			response.headers().add<Pistache::Http::Header::ContentType>(Pistache::Http::Mime::MediaType("application/json"));
			response.send(Pistache::Http::Code::Ok, R"({"message": "login successful"})");
		} else {
				_mysqlPool -> releaseConnection(connPtr);
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

		// =============== add to set =======================
		std::cerr<<"[Login INFO] Successed Register! User: "<<name<<std::endl;
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
		std::shared_ptr<Mysql> mysql_ptr = _mysqlPool -> getConnection();
		std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
		std::string filename = j.value("filename","");
		std::string md5 = j.value("md5","");
		std::string user = j.value("name","");
		if (redis_ptr->get(md5) != "") { //系统中有文件
			// in MySQL and in UserList
			if (mysql_ptr->isInUserList(md5, user)) { //用户有该文件
				std::cerr<<"[UploadCheck INFO] "<<"user: "<<user<<" already owned File"<<std::endl;
				_mysqlPool->releaseConnection(mysql_ptr);
				_redisPool -> releaseConnection(redis_ptr);
				response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
                return;
			} else { // 系统中有文件，用户没有文件
				// 秒传：插入关系 + 引用计数+1
                if (mysql_ptr->insertUserFile(md5, user, filename) && mysql_ptr->updateCount(md5, 1)) {
					std::cerr<<"[UploadCheck INFO] Database already owned File"<<std::endl;
					_mysqlPool->releaseConnection(mysql_ptr);
					_redisPool -> releaseConnection(redis_ptr);
					response.send(Pistache::Http::Code::Ok,
						R"({"success":true,"status":"instant_upload"})",
						MIME(Application, Json));
					return;
				}
			}
		} else { //redis 中没有该文件
			if (mysql_ptr->isInMySQL(md5)){ //数据库中有该文件
				int count = 0;
				std::string url = "";
				mysql_ptr -> getCount(md5, count, url);
				redis_ptr -> set(md5,url, 3306);
				// 用户也有该文件
				if (mysql_ptr->isInUserList(md5, user)) {
		 			std::cerr<<"[UploadCheck INFO] "<<"user: "<<user<<" already owned File"<<std::endl;
		 			_redisPool -> releaseConnection(redis_ptr);
					_mysqlPool->releaseConnection(mysql_ptr);
		 			response.send(Pistache::Http::Code::Ok,
                		R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
                 	return;
				} else { //用户没有该文件
					// 秒传：插入关系 + 引用计数+1
					if (mysql_ptr->insertUserFile(md5, user, filename) && mysql_ptr->updateCount(md5, 1)) {
						std::cerr<<"[UploadCheck INFO] Database already owned File"<<std::endl;
						_redisPool -> releaseConnection(redis_ptr);
						_mysqlPool->releaseConnection(mysql_ptr);
						response.send(Pistache::Http::Code::Ok,
							R"({"success":true,"status":"instant_upload"})",
							MIME(Application, Json));
						return;
					} else {
						response.send(Pistache::Http::Code::Internal_Server_Error,
                        R"({"success":false,"message":"failed to link file"})",
                        MIME(Application, Json));
                    	return;
					}
				}
			}
		}
		std::cerr<<"[UploadCheck INFO] Database have no File"<<std::endl;
		_mysqlPool-> releaseConnection(mysql_ptr);
		_redisPool -> releaseConnection(redis_ptr);
		response.send(Pistache::Http::Code::Ok,
        	R"({"success":true,"status":"need_upload"})",
        	MIME(Application, Json));

	}catch (const std::exception& e) {
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
		
		std::shared_ptr<Mysql> connPtr = _mysqlPool -> getConnection();

		if (!connPtr->beginTransaction()) {
			// 事务开启失败，需要清理 FastDFS 上已上传的文件
			//fdfs_ptr -> delete_file_from_fastdfs();
			_mysqlPool->releaseConnection(connPtr);
			return;
		}
		//入数据库
		std::shared_ptr<FdfsClient> fdfs_ptr = _fdfsPool -> getConnection();
		std::string temp_path = fdfs_ptr -> create_temp_file(fileData);
		if (temp_path.empty()) {
           response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"/write /tmp/ false"})",
                MIME(Application, Json));
            return;
        }
		const char* ext = strrchr(filename.c_str(),'.');
		const char* file_ext = ext?ext+1:"";
		//upload
		std::string fastdfs_path = fdfs_ptr -> upload_file_to_fastdfs(temp_path.c_str(), file_ext);
		//std::string fastdfs_path = upload_file_to_fastdfs(temp_path.c_str());
		if (fastdfs_path.empty()) {
			_fdfsPool -> releaseConnection(fdfs_ptr);
           	response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"upload to fastdfs false"})",
                MIME(Application, Json));
            return;
        }
		//delete tem file
		std::filesystem::remove(temp_path);
		_fdfsPool -> releaseConnection(fdfs_ptr);

		bool db_success = false;
		if (!(connPtr -> insertUserFile(md5, user, filename))){
			std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<user<<"file: "<<filename<<"to user_file_list"<<std::endl;
		}
		if (!(connPtr -> insertFileInfo(md5, fastdfs_path, file_ext))){
			std::cerr<<"[MySQL ERROE] Failed Insert file: "<<filename<<"to file_info" <<std::endl;
		}
		db_success = true;
		

		if (!(connPtr -> commit())) {
			db_success = false;
			std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
		}
		if (!db_success) {
			connPtr->rollback();
			std::cerr << "[MySQL INFO] Transaction rolled back." << std::endl;
			//std::string url = fastdfs_path;
			deleteFiles(fastdfs_path); 
			_mysqlPool -> releaseConnection(connPtr);
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"数据库操作失败或事务提交失败，文件已回滚"})",
				MIME(Application, Json));
		}

		_mysqlPool -> releaseConnection(connPtr);
		
		//插入redis
		// std::string url = fastdfs_path + ext;
		// std::string value = url;
		std::shared_ptr<Redis> redisConn = _redisPool->getConnection();
		//std::cout << fastdfs_path << std::endl;
		if (!(redisConn -> set(md5, fastdfs_path, 3600))) {
			_redisPool -> releaseConnection(redisConn);
			response.send(Pistache::Http::Code::Bad_Request,
             R"({"success":false,"message":"请先调用 /upload/check"})",
             MIME(Application, Json));
             return;
		}
		_redisPool -> releaseConnection(redisConn);
		// 构造 JSON 对象
		json responseJson = {
    		{"success", true},
    		{"message", "file uploaded successfully"},
    		{"url", "http://146.56.194.96/" + fastdfs_path},
    		{"fastdfs_path", fastdfs_path+file_ext}
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

void Api::queryUserFiles(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response){
	try{

		auto userOpt = req.query().get("user");
		if (!userOpt.has_value()) {
        	response.send(Pistache::Http::Code::Bad_Request, "Missing 'user' parameter");
        	return;
    	}
    	std::string username = userOpt.value();
		
		json array = json::array();

		std::shared_ptr<Mysql> connPtr = _mysqlPool->getConnection();

		connPtr -> queryUserFiles(username, array);
		_mysqlPool -> releaseConnection(connPtr);
		// 转为字符串并返回
        std::string jsonString = array.dump();
		
		// 3. 返回JSON给前端（前端loadFiles()可直接解析）
		response.headers().add<Pistache::Http::Header::ContentType>(
			Pistache::Http::Mime::MediaType("application/json"));
    	response.send(Pistache::Http::Code::Ok, jsonString);
	}
	catch (const std::exception& e) {
		std::cerr << "Error in queryUserFiles: " << e.what() << std::endl;
        response.send(Pistache::Http::Code::Internal_Server_Error, "Server error");
	}
}

// ==================Delete / deleteFiles ================
void Api::deleteCheck(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	bool success = false;
	try {
		auto userOpt = req.query().get("user");
        auto idOpt   = req.query().get("id");

        if (!userOpt || !idOpt) {
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"Missing user or id"})",
                MIME(Application, Json));
            return;
        }

        std::string user = userOpt.value();
        std::string md5  = idOpt.value();
		
		if (user.empty() || md5.empty()) {
            response.send(Pistache::Http::Code::Bad_Request, "Missing user or id");
            return;
        }

		std::shared_ptr<Mysql> connPtr = _mysqlPool->getConnection();
		connPtr -> deleteUserFile(user, md5); // 先给用户删除
		std::cout << "[MySQL INFO] Successed user: "<<user<<" deleted file: "<< md5<< std::endl;
		connPtr -> updateCount(md5, -1); // 给文件 count -1;
		int count = 0;
		std::string url;
		if (connPtr -> getCount(md5, count, url)) {
			std::cout << "[MySQL INFO] Successed file: "<<md5<<" update count: "<<count<<std::endl;
		} else {
			std::cout << "[MySQL INFO] Failed file: "<<md5<<" update count: "<<count<<std::endl;
		}
		_mysqlPool -> releaseConnection(connPtr);
		if (count == 0) { // 已经没有用户需要这个文件
			//this->deleteFiles(url, md5); // 从 redis fdfs 中删除
			this->deleteFiles(url);
			std::shared_ptr<Redis> redis_ptr = _redisPool->getConnection();
			redis_ptr -> del(md5);
			_redisPool -> releaseConnection(redis_ptr);
			connPtr -> deleteSysFile(md5); // 从 file_info 中删除
			std::cerr<<"[MySQL INFO] "<<"Successed user: "<<user<<" delete file: "<<md5<<std::endl;
			response.send(
            	Pistache::Http::Code::Ok,
            	R"({"success":true,"message":"File deleted successfully"})",
            	MIME(Application, Json)
        	);
		} else {
			response.send(
            Pistache::Http::Code::Ok,
            R"({"success":true,"message":"user_file_list deleted"})",
            MIME(Application, Json)
        	);
		}
	} catch (const std::exception& e) {
		response.send(Pistache::Http::Code::Internal_Server_Error,
            R"({"success":false,"message":"服务器异常"})",
            MIME(Application, Json));
	}
}

void Api::deleteFiles(const std::string& url){
	// 删除 fdsf 系统文件
	size_t firstSlash = url.find('/');
	if (firstSlash == std::string::npos) {
		std::cerr << "[ERROR] Invalid FastDFS URL format (no '/'): \"" << url << "\"" << std::endl;
		return;
	}

	std::string group_name = url.substr(0, firstSlash);
	std::string remote_file = url.substr(firstSlash+1);
	std::shared_ptr<FdfsClient> connFdfs = _fdfsPool->getConnection();
	if( connFdfs -> delete_file_from_fastdfs(group_name, remote_file) ) {
		std::cout << "[Fdfs INFO] Successfully deleted FastDFS file: group=\"" 
              << group_name << "\", file=\"" << remote_file << "\"" << std::endl;
	} else {
		std::cerr << "[Fdfs ERROR] Failed to delete FastDFS file: group=\"" 
              << group_name << "\", file=\"" << remote_file << "\"" << std::endl;
		return;  // 跳过redis
	}

	_fdfsPool -> releaseConnection(connFdfs);
}
