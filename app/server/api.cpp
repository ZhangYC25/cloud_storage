#include <curl/curl.h>

#include "api.h"
#include "session.h"
#include "../utils/utils.h"
//#include "email.h"


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

	Routes::Post(router, "/api/email", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            // 在 Lambda 内部调用成员函数
            this->registerEmail(req, std::move(response));
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
    std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try {
		auto body = req.body();
		json j = json::parse(body);
        std::string stored_hash;

		std::string username = j.value("name", "");
		//std::string nickname = j.value("nickname", "");
		std::string password = j.value("password", "");
		
		if (username.empty() || password.empty()) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "missing username or password"})");
			_redisPool -> releaseConnection(redis_ptr);
			_mysqlPool -> releaseConnection(mysql_ptr);
			return;
        }

		if (!(mysql_ptr -> getUserPasswordHash(username, stored_hash))) {
			response.send(Pistache::Http::Code::Unauthorized, R"({"error": "invalid credentials"})");
			_redisPool -> releaseConnection(redis_ptr);
			_mysqlPool -> releaseConnection(mysql_ptr);
			return;
		}
		
		if (bcrypt_checkpw(password.c_str(), stored_hash.c_str()) == 0) {
					
			std::shared_ptr<Session> session_ptr = std::make_shared<Session>();
			session_ptr -> createSession(username);
			auto it = _sessions.find(username);
			if (it == _sessions.end()){
				//说明用户第一次登录 或者 上传登录已经过期
				_sessions[username] = session_ptr;
			} else { //找到了，说明上传登录的信息还残留
				_sessions.erase(it);
				_sessions[username] = session_ptr;
				std::cerr<<"[Session INFO] _session size: "<<_sessions.size()<<std::endl;
			}
		
			//只要是登录就加入redis
			// 添加到redis <sessionId, username>
			redis_ptr -> set(session_ptr->getSession(), username, 600);
			_redisPool -> releaseConnection(redis_ptr);

			std::string sessionId = session_ptr->getSession();

			std::cerr<<"[Login INFO] Successed login! User: "<<username<<" session:"<<sessionId<<std::endl;
			_mysqlPool -> releaseConnection(mysql_ptr);

			Pistache::Http::Cookie cookie("session", sessionId);
			cookie.httpOnly = true;
			cookie.secure = true;
			cookie.maxAge = 600; 
			cookie.path = "/";
			response.cookies().add(cookie);
			//response.headers().add<Pistache::Http::Header::ContentType>(Pistache::Http::Mime::MediaType("application/json"));
			response.send(Pistache::Http::Code::Ok, R"({"message": "login successful"})");
		} else {
				_mysqlPool -> releaseConnection(mysql_ptr);
				_redisPool -> releaseConnection(redis_ptr);
				response.send(Pistache::Http::Code::Unauthorized, R"({"error": "invalid credentials"})");
		}
	} catch (const std::exception& e) {
		response.send(Pistache::Http::Code::Bad_Request, R"({"error":"invalid json"})");
		_mysqlPool -> releaseConnection(mysql_ptr);
		_redisPool -> releaseConnection(redis_ptr);
		return;
	}
} 

// ========= POST /login =========
void Api::registerEmail(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	//std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
	const std::string REDIS_KEY_PREFIX = "email_verify_code:";
	bool needReleaseRedis = true;
	try {
		auto body = req.body();
		json j = json::parse(body);
		std::string userEmail = j.value("email","");
		std::string name = j.value("name","");

		{
		if (!isValidEmail(userEmail)) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "please input valid email"})");
		}
		//check name
		if (name.length() < 3 || name.length() > 20) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "name must be 3-20 characters"})");
			return;
		}

		if(mysql_ptr -> queryUser(name)){  //如果数据库有该用户名，不行
			response.send(Pistache::Http::Code::Conflict, R"({"error": "name has existed"})");
			return;
		}

		if(mysql_ptr -> queryEmail(userEmail)) { ////如果数据库有该邮箱，不行
			response.send(Pistache::Http::Code::Conflict, R"({"error": "email has existed"})");
			return;
		}
		_mysqlPool -> releaseConnection(mysql_ptr);
		}
		response.send(Pistache::Http::Code::Ok, R"({"message": "send verify succeeded"})");

		// ================== 暂时 不用 ==========================

		//std::string code = generateSixDigitCode();

		//std::string key = REDIS_KEY_PREFIX+userEmail;
		//std::string value = code + "|" + name;
		//redis_ptr -> set(key, value, 310);

		//Email* email = new Email(userEmail, name, code);
		//<email, code>
		//std::string emiresponse = email->sendTencentSESEmail();
		// if (emiresponse.find("Error") != std::string::npos) {
		// 	response.send(Pistache::Http::Code::Bad_Request, R"({"error": "send verify failed"})");
		// 	std::cerr << "邮件发送失败,删除Redis中的验证码" << std::endl;
		// 	// 调用删除Redis的函数（下面会写）
		// 	redis_ptr -> del(REDIS_KEY_PREFIX+userEmail);
		// 	//deleteCodeFromRedis(toEmail);
		// } else {
		// 	std::cout << "邮件发送成功，验证码已存储" << std::endl;
		// 	response.send(Pistache::Http::Code::Ok, R"({"message": "send verify succeeded"})");
		// }

		// needReleaseRedis = false;
		// _redisPool -> releaseConnection(redis_ptr);
		// delete email;
		return;
	} catch(const std::exception& e){
		//_redisPool -> releaseConnection(redis_ptr);
		response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
	}

	// 兜底：确保Redis连接被释放（防止try块内的异常导致未释放）
    if (needReleaseRedis) {
        try {
            //_redisPool->releaseConnection(redis_ptr);
        } catch (...) {
            std::cerr << "释放Redis连接失败" << std::endl;
        }
    }
	return;
}



void Api::registerUser(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	const std::string REDIS_KEY_PREFIX = "email_verify_code:";
	try{
		auto body = req.body();
		json j = json::parse(body);

		std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
		std::shared_ptr<Redis> redis_ptr = _redisPool ->getConnection();
		std::string name = j.value("name","");
		std::string password = j.value("password","");
		std::string email = j.value("email", "");
		//std::string code = j.value("code", "");

		if (!isValidEmail(email)) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "please input valid email"})");
		}
		//check name
		if (name.length() < 3 || name.length() > 20) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "name must be 3-20 characters"})");
			return;
		}

		if(mysql_ptr -> queryUser(name)){  //如果数据库有该用户名，不行
			response.send(Pistache::Http::Code::Conflict, R"({"error": name has existed!})");
			return;
		}

		if(mysql_ptr -> queryEmail(email)) { ////如果数据库有该邮箱，不行
			response.send(Pistache::Http::Code::Conflict, R"({"error": email has existed!})");
			return;
		}
// ====================== 邮箱认证 =================================
		// 可选：确保全是数字
		// if (!std::all_of(code.begin(), code.end(), ::isdigit)) {
		// 	response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid vervify"})");
		// 	return;
		// }

		// std::string key = REDIS_KEY_PREFIX + email;
		// std::string redis_verify = redis_ptr -> get(key);
		// if (redis_verify == "") {
		// 	response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid or outtime"})");
    	// 	return;
		// }

		// std::string redisUser;
		// std::string redisCode;
		// std::stringstream ss(redis_verify);
		// getline(ss, redisCode, '|');
		// getline(ss, redisUser);

		// if (!(redisCode == code)) {
		// 	response.send(Pistache::Http::Code::Bad_Request, R"({"error": "error"})");
    	// 	return;
		// }

		// if (!(redisUser == name)) {
		// 	response.send(Pistache::Http::Code::Bad_Request, R"({"error": "error"})");
    	// 	return;
		// }


		char hash[BCRYPT_HASHSIZE];
		char salt[BCRYPT_HASHSIZE] = {0}; // 盐值缓冲区
		if (bcrypt_gensalt(12, salt)) { // 先生成盐值
    			response.send(Pistache::Http::Code::Internal_Server_Error, R"({"error": "generate salt failed"})");
    			return;
			}
		if (isWeakPassword(password)) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "password is too weak"})");
			return;
		}
		if (!isStrongPassword(password)) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "password must be at least 8 characters and 
		contain at least 3 of: lowercase, uppercase, digit, special character"})");
			return;
		}
		if (bcrypt_hashpw(password.c_str(), salt, hash) != 0) { 
			// 用生成的盐值计算哈希
    			response.send(Pistache::Http::Code::Internal_Server_Error, R"({"error": "hash failed"})");
    			return;
		}

		if (!(mysql_ptr->insertUser(name, std::string(hash), email))) {
			response.send(Pistache::Http::Code::Conflict, R"({"error": "name already taken or db error"})");
			return;
		}

		// =============== add to set =======================
		std::cerr<<"[Login INFO] Successed Register! User: "<<name<<std::endl;
		_mysqlPool->releaseConnection(mysql_ptr);

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
		//std::string user = j.value("name","");

		auto& cookies = req.cookies();
		std::string sessionId = "";
		if (cookies.has("session")) {
			sessionId = cookies.get("session").value;
			// 验证 sessionId 是否有效...
		} else {
			std::cerr<<"[UploadCheck ERROR] "<<"invalid session"<<std::endl;
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
		}
		std::string user = redis_ptr -> get(sessionId);
		redis_ptr -> expire(sessionId, 600);
		//std::string file_redis = redis_ptr->get(md5);

		std::cerr<<"user: "<<user<<" session: "<< sessionId <<std::endl;

		if (mysql_ptr -> isInUserList(md5, user)) { // 先查 userfile 命中的话其他根本不用查。
			std::cerr<<"[UploadCheck INFO] "<<"user: "<<user<<" already owned File"<<std::endl;
				response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
		} else if (mysql_ptr -> isInMySQL(md5)) { //能找到这里说明 用户肯定没有这个文件 在查 系统表有没有这个文件，有的话
			if (redis_ptr->get(md5)== "") { // 在查 redis 有没有这个文件，没有就重新插进去
				int count = 0;
				std::string url = "";
				mysql_ptr -> getCount(md5, count, url);
				redis_ptr -> set(md5,url, 3600);
			}
			// 秒传，count + 1
			if (!(mysql_ptr -> beginTransaction())) {
					_mysqlPool->releaseConnection(mysql_ptr);
					_redisPool -> releaseConnection(redis_ptr);
					return;
				}

				if (!(mysql_ptr -> insertUserFile(md5, user, filename))) {
					std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<
					user<<"file: "<<filename<<"to user_file_list"<<std::endl;
				}
				if (!(mysql_ptr -> updateCount(md5, 1))){
					std::cerr<<"[MySQL ERROR]  Failed Update count for file: "<<filename<<std::endl;
				}
				bool db_success = true;
				if (!(mysql_ptr -> commit())) {
					db_success = false;
					std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
				}
				if (!db_success) {
					mysql_ptr->rollback();
					std::cerr << "[MySQL INFO] Transaction rolled back." << std::endl;
					response.send(Pistache::Http::Code::Internal_Server_Error,
						R"({"success":false,"message":"数据库操作失败或事务提交失败，文件已回滚"})",
						MIME(Application, Json));
				} else {
					response.send(Pistache::Http::Code::Ok,
					R"({"success":true,"status":"instant_upload"})",MIME(Application, Json));
				}
		} else { //不在 系统表，不管redis在不在， 肯定需要上传
			response.send(Pistache::Http::Code::Ok,
        	R"({"success":true,"status":"need_upload"})",
        	MIME(Application, Json));
		}
		_mysqlPool-> releaseConnection(mysql_ptr);
		_redisPool -> releaseConnection(redis_ptr);
		return;
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

        std::string filename, md5;// user;
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

            pos = nextBoundary;
        }

        if (fileData.empty()) {
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"文件为空"})",
                MIME(Application, Json));
            return;
        }
		
		auto& cookies = req.cookies();
		std::string sessionId = "";
		if (cookies.has("session")) {
			sessionId = cookies.get("session").value;
			// 验证 sessionId 是否有效...
		} else {
			std::cerr<<"[UploadCheck ERROR] "<<"invalid session"<<std::endl;
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
		}
		std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
		std::string user = redis_ptr -> get(sessionId);
		redis_ptr -> expire(sessionId, 600);

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
		std::cerr<<"here1"<<std::endl;
		const char* ext = strrchr(filename.c_str(),'.');
		const char* file_ext = ext?ext+1:"";
		//upload
		std::cerr<<"here2"<<std::endl;
		std::string fastdfs_path = fdfs_ptr -> upload_file_to_fastdfs(temp_path.c_str(), file_ext);
		std::cerr<<"user: "<< user <<" up file"<<std::endl;
		//std::string fastdfs_path = upload_file_to_fastdfs(temp_path.c_str());
		std::cerr<<"here3"<<std::endl;
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
		auto& cookies = req.cookies();
		std::string sessionId = "";
		if (cookies.has("session")) {
			sessionId = cookies.get("session").value;
			// 验证 sessionId 是否有效...
		} else {
			std::cerr<<"[UploadCheck ERROR] "<<"invalid session"<<std::endl;
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
		}
		std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
		std::string username = redis_ptr -> get(sessionId);
		redis_ptr -> expire(sessionId, 600);
		_redisPool->releaseConnection(redis_ptr);
		
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

	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();

	try {
		//auto userOpt = req.query().get("user");
        auto idOpt   = req.query().get("id");

        //if (!userOpt || !idOpt) {
		if (!idOpt) {
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"Missing user or id"})",
                MIME(Application, Json));
            return;
        }

        //std::string user = userOpt.value();
        std::string md5  = idOpt.value();

		auto& cookies = req.cookies();
		std::string sessionId = "";
		if (cookies.has("session")) {
			sessionId = cookies.get("session").value;
			// 验证 sessionId 是否有效...
		} else {
			std::cerr<<"[UploadCheck ERROR] "<<"invalid session"<<std::endl;
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
		}
		std::string user = redis_ptr -> get(sessionId);
		redis_ptr -> expire(sessionId, 600);
		
		if (user.empty() || md5.empty()) {
            response.send(Pistache::Http::Code::Bad_Request, "Missing user or id");
            return;
        }

		std::shared_ptr<Mysql> connPtr = _mysqlPool->getConnection();
		connPtr -> deleteUserFile(user, md5); // 先给用户删除
		std::cout << "[MySQL INFO] Successed user: "<<user<<" deleted file: "<< md5<< std::endl;
		connPtr -> updateCount(md5, -1); // 给文件 count -1;
		std::cerr<<"user: "<< user <<" delete file"<<std::endl;
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
