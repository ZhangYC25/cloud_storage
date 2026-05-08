#include <curl/curl.h>
#include<iostream>
#include "api.h"
#include "session.h"
#include "../utils/utils.h"
#include "../utils/file.hpp"
//#include "../utils/threadPool.h"

//#include "email.h"


std::shared_ptr<Api> Api::_apiInstance = nullptr;
std::mutex Api::_instanceMtx;

std::shared_ptr<Api> Api::getInstance(){
	if (_apiInstance == nullptr) {
		static std::mutex instanceMutex;
		std::lock_guard<std::mutex> lock(instanceMutex);
		if (_apiInstance == nullptr) {
                std::shared_ptr<Api> instance(new Api());
				//std::shared_ptr<Api> instance = std::make_shared<Api>();
				_apiInstance = instance;
            }	
	}
	return _apiInstance;
}

void Api::destroyInstance(){
	std::lock_guard<std::mutex> lock(_instanceMtx); // 注意这里用的是保护单例的静态锁
    if (_apiInstance) {
        _apiInstance.reset();
    }
}

void Api::shutdown() {
    this->running.store(false); 
    this->_cv.notify_all(); // 这一行是“叫醒服务”，非常重要！
}


Api::Api(){ 
	_mysqlPool = MySQLConnPool::getInstance();
	_fdfsPool = FdfsConnPool::getInstance();
	_redisPool = RedisConnPool::getInstance();
	_pthreadPool = uploadThreadPool::getInstance();

	_pthreadPool -> submit([this](){
		this -> healthCheckLoop();
	});
	
}

void Api::healthCheckLoop() {
    std::this_thread::sleep_for(std::chrono::minutes(1));

    while (running.load()) {
        MY_LOG_INFO("Starting daily consistency check...");
        
        // 执行实际的数据库与 FDFS 对比逻辑
        this->runConsistencyCheck(); 

        // 关键点：这里不再使用 sleep，而是使用 wait_for
        std::unique_lock<std::mutex> lock(_mtx);
        bool stopped = _cv.wait_for(lock, std::chrono::hours(24), [this] {
            return !this->running.load(); // 如果收到 shutdown，这里返回 true，停止等待
        });

        if (stopped || !running.load()) {
            break; // 优雅退出循环
        }
    }
    MY_LOG_INFO("Health Check task exited safely.");
}

// 在 Api 类中（私有方法）
bool Api::validateUploadSession(const Pistache::Rest::Request& req, const std::string& upload_user_key,
                                std::shared_ptr<Redis> redis_ptr, std::string& user_name) {
	user_name.clear();

    auto& cookies = req.cookies();
    if (!cookies.has("session")) {
        MY_LOG_ERROR("Upload request missing session cookie");
        return false;
    }

    std::string sessionId = cookies.get("session").value;
    if (sessionId.empty()) {
        MY_LOG_ERROR("Session cookie is empty");
        return false;
    }

    std::string session_user_key = "user:" + sessionId;
    user_name = redis_ptr->get(session_user_key);
    redis_ptr -> expire(session_user_key, 600);
	if (user_name.empty()) {
        MY_LOG_ERROR("Invalid or expired session: ", sessionId);
        return false;
    }

    if (!upload_user_key.empty()) {
        std::string key_owner = redis_ptr->get(upload_user_key);
        if (key_owner != user_name) {
            MY_LOG_ERROR("Upload session mismatch: session user='", user_name,
                         "', but upload_user_key belongs to='", key_owner, "'");
            return false;
        }
    }
    return true;
}

void Api::runConsistencyCheck() {
    MY_LOG_INFO("=== [Health Check] Task Started ===");
    
    int offset = 0;
    const int batch_size = 100;
    int total_checked = 0;
    std::vector<std::string> corrupted_md5s;

    // 获取数据库和FDFS连接
    auto mysql_ptr = _mysqlPool->getConnection();
    auto fdfs_ptr = _fdfsPool->getConnection();

    while (true) {
        std::vector<FileRecord> batch = mysql_ptr->getFileRecordsBatch(batch_size, offset);
        if (batch.empty()) break; // 查完了

        for (const auto& record : batch) {
            total_checked++;
            
            if (!fdfs_ptr->check_file_exists(record.url)) {
                corrupted_md5s.push_back(record.md5);
                MY_LOG_ERROR("[ALARM] Physical file missing! MD5: ", record.md5, " URL: ", record.url);
            }
        }

        offset += batch_size;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    _mysqlPool->releaseConnection(mysql_ptr);
    _fdfsPool->releaseConnection(fdfs_ptr);

    MY_LOG_INFO("=== [Health Check] Summary ===");
    MY_LOG_INFO("Total files scanned: ", total_checked);
    if (corrupted_md5s.empty()) {
        MY_LOG_INFO("Result: ALL DATA HEALTHY.");
    } else {
        MY_LOG_ERROR("Result: FOUND ", corrupted_md5s.size(), " CORRUPTED RECORDS.");
    }
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

	Routes::Post(router, "/api/upload/init", 
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			this -> largeInit(req, std::move(response));
			return Route::Result::Ok;
		}
	);

	Routes::Post(router, "/api/upload/chunk",
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			this -> largeFileUpload(req, std::move(response));
			return Route::Result::Ok;
		}
	);

	Routes::Post(router, "/api/upload/finish",
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			this -> uploadLargeFileFinish(req, std::move(response));
			return Route::Result::Ok;
		}
	);

	Routes::Post(router, "/api/upload/query",
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			this -> queryFileURL(req, std::move(response));
			return Route::Result::Ok;
		});
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
		
			//只要是登录就加入redis
			// 添加到redis <sessionId, username>
			std::string sessionId = session_ptr->getSession();
			std::string key = "user:" + sessionId;
			redis_ptr -> set(key, username, 600);
			_redisPool -> releaseConnection(redis_ptr);

			std::cerr<<"[Login INFO] Successed login! User: "<<username<<" session:"<<sessionId<<std::endl;
			_mysqlPool -> releaseConnection(mysql_ptr);

			Pistache::Http::Cookie cookie("session", sessionId);
			cookie.httpOnly = true;
			cookie.secure = true;
			//cookie.maxAge = 600; 
			//cookie.path = "/";
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
			MY_LOG_ERROR("Redis Release connection failed");
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
// ============================================================================

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
		//MY_LOG_INFO("Login Successed Register! User: ", name);
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
	std::cout<<"uploadCheck start"<<std::endl;
	std::shared_ptr<Mysql> mysql_ptr = _mysqlPool -> getConnection();
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try{
		auto body = req.body(); //filename md5 filesize;
		json j = json::parse(body);
		std::string filename = j.value("filename","");
		std::string md5 = j.value("md5","");

		std::string user = "";
		if (!validateUploadSession(req, "", redis_ptr, user)){
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

		if (mysql_ptr -> isInUserList(md5, user)) { // 先查 userfile 命中的话其他根本不用查。
			std::cerr<<"[UploadCheck INFO] "<<"user: "<<user<<" already owned File"<<std::endl;
			//MY_LOG_INFO("UploadCheck user: ", user, "already owned File");
				response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
		} else if (mysql_ptr -> isInMySQL(md5)) { //能找到这里说明 用户肯定没有这个文件 在查 系统表有没有这个文件，有的话
			std::string md5_key = "md5:" + md5;
			if (redis_ptr->get(md5_key)== "") { // 在查 redis 有没有这个文件，没有就重新插进去
				int count = 0;
				std::string url = "";
				mysql_ptr -> getCount(md5, count, url);
				redis_ptr -> set(md5_key,url, 3600);
			}
			// 秒传，count + 1
			if (!(mysql_ptr -> beginTransaction())) {
					_mysqlPool->releaseConnection(mysql_ptr);
					_redisPool -> releaseConnection(redis_ptr);
					return;
				}

				if (!(mysql_ptr -> insertUserFile(md5, user, filename))) {
					// std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<
					// user<<"file: "<<filename<<"to user_file_list"<<std::endl;
					//MY_LOG_ERROR("MySQL Failed Insert file for user: ")
				}
				if (!(mysql_ptr -> updateCount(md5, 1))){
					//std::cerr<<"[MySQL ERROR]  Failed Update count for file: "<<filename<<std::endl;
				}
				bool db_success = true;
				if (!(mysql_ptr -> commit())) {
					db_success = false;
					//std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
				}
				if (!db_success) {
					mysql_ptr->rollback();
					//std::cerr << "[MySQL INFO] Transaction rolled back." << std::endl;
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
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try {	
		auto file_name_header = req.headers().tryGetRaw("X-Filename");
		auto file_md5 = req.headers().tryGetRaw("X-File-MD5");
		
		if (!file_name_header || !file_md5) {
			response.send(Pistache::Http::Code::Bad_Request,
				R"({"success":false,"message":"Missing X-Filename or X-File-MD5"})",
				MIME(Application, Json));
			return;
		}
		std::string file_name   = url_decode(file_name_header -> value());
		std::string md5         = file_md5 -> value();
		
		auto& cookies = req.cookies();
		std::string user = "";
		if (!validateUploadSession(req, "", redis_ptr, user)){
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

		auto body = req.body();

		std::shared_ptr<Mysql> mysql_ptr = _mysqlPool -> getConnection();

		if (!mysql_ptr->beginTransaction()) {
			// 事务开启失败，需要清理 FastDFS 上已上传的文件
			//fdfs_ptr -> delete_file_from_fastdfs();
			_mysqlPool->releaseConnection(mysql_ptr);
			return;
		}
		//入数据库
		std::shared_ptr<FdfsClient> fdfs_ptr = _fdfsPool -> getConnection();
		std::string temp_path = fdfs_ptr -> create_temp_file(body);
		if (temp_path.empty()) {
           response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"/write /tmp/ false"})",
                MIME(Application, Json));
            return;
        }
		const char* ext = strrchr(file_name.c_str(),'.');
		const char* file_ext = ext?ext+1:"";
		//upload
		std::string fastdfs_path = fdfs_ptr -> upload_file_to_fastdfs(temp_path.c_str(), file_ext);
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
		if (!(mysql_ptr -> insertUserFile(md5, user, file_name))){
			//std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<user<<"file: "<<filename<<"to user_file_list"<<std::endl;
		}
		if (!(mysql_ptr -> insertFileInfo(md5, fastdfs_path, file_ext))){
			//std::cerr<<"[MySQL ERROE] Failed Insert file: "<<filename<<"to file_info" <<std::endl;
		}
		db_success = true;
		

		if (!(mysql_ptr -> commit())) {
			db_success = false;
			//std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
		}
		if (!db_success) {
			mysql_ptr->rollback();
			//std::cerr << "[MySQL INFO] Transaction rolled back." << std::endl;
			//std::string url = fastdfs_path;
			deleteFiles(fastdfs_path); 
			_mysqlPool -> releaseConnection(mysql_ptr);
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"数据库操作失败或事务提交失败，文件已回滚"})",
				MIME(Application, Json));
		}

		_mysqlPool -> releaseConnection(mysql_ptr);

		//std::shared_ptr<Redis> redisConn = _redisPool->getConnection();
		//std::cout << fastdfs_path << std::endl;
		if (!(redis_ptr -> set(md5, fastdfs_path, 3600))) {
			_redisPool -> releaseConnection(redis_ptr);
			response.send(Pistache::Http::Code::Bad_Request,
             R"({"success":false,"message":"请先调用 /upload/check"})",
             MIME(Application, Json));
             return;
		}
		_redisPool -> releaseConnection(redis_ptr);
		// 构造 JSON 对象
		json responseJson = {
    		{"success", true},
    		{"message", "file uploaded successfully"},
    		//{"url", "http://146.56.194.96/" + fastdfs_path},
			{"url", "https://goodfloat.cloud/" + fastdfs_path},
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

// ===============================POST / large upload
// ============== 可以做断点续传 =============
void Api::largeInit(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection(); 
	try {
		std::string user = "";
		if (!validateUploadSession(req, "", redis_ptr, user)) {
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session"})",
                    MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

		auto body = req.body();
		json j = json::parse(body);
		std::string filename = j.value("filename", "");
		uint64_t total_chunks = j.value("size", 0ULL);
		std::string md5 = j.value("md5", "");
		std::string file_ext = j.value("ext", "");

		if (total_chunks == 0) {
        	response.send(Pistache::Http::Code::Bad_Request, 
				R"({"success":false,"message":"size is null"})",
                    MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
        	return;
    	}

		std::string upload_id = generate_upload_id();
		std::string temp_dir = TEMP_BASE_DIR + "/" + upload_id;
		std::filesystem::create_directories(temp_dir);

		std::string info_key = "upload:" + upload_id + ":info";
		std::string status_key = "upload:" + upload_id + ":status";
		std::string upload_user_key = md5 + upload_id + ":ID";

		redis_ptr -> set(upload_user_key, user, 3600);
		redis_ptr -> set(status_key, "initial", 3600);

		if (redis_ptr -> hset(info_key, "filename", filename) &&
        	redis_ptr -> hset(info_key, "temp_dir", temp_dir) &&
        	redis_ptr -> hset(info_key, "total_chunks", std::to_string(total_chunks)) &&
        	redis_ptr -> hset(info_key, "md5", md5) &&
			redis_ptr -> hset(info_key, "file_ext", file_ext)) {
			nlohmann::json res;
			res["upload_id"] = upload_id;
			response.send(Pistache::Http::Code::Ok, res.dump(), MIME(Application, Json));
		}
	} catch (const std::exception& e) {
        response.send(Pistache::Http::Code::Bad_Request,
                      R"({"success":false,"message":"Invalid JSON"})",
                      MIME(Application, Json));
    } catch (...) {
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"Server error"})",
                      MIME(Application, Json));
    }
	_redisPool -> releaseConnection(redis_ptr);
	return;
}

//std::chrono::_V2::system_clock::time_point responseTime;

void Api::largeFileUpload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try {
		auto upload_id_header = req.headers().tryGetRaw("X-Upload-ID");
		auto index_header = req.headers().tryGetRaw("X-Chunk-Index");
		auto file_md5 = req.headers().tryGetRaw("X-File-MD5");
		
		if (!upload_id_header || !index_header || !file_md5) {
			response.send(Pistache::Http::Code::Bad_Request,
				R"({"success":false,"message":"Missing X-Upload-ID or X-Chunk-Index"})",
				MIME(Application, Json));
			return;
		}
		std::string upload_id   = upload_id_header -> value();
		std::string chunk_index = index_header -> value();
		std::string md5         = file_md5 -> value();

		std::string info_key   = "upload:" + upload_id + ":info";
        std::string chunks_key = "upload:" + upload_id + ":chunks";
		std::string status_key = "upload:" + upload_id + ":status";
		std::string upload_user_key = md5 + upload_id + ":ID";

		std::string user = "";
		if (!validateUploadSession(req, upload_user_key, redis_ptr, user)) {
        	response.send(Pistache::Http::Code::Unauthorized,
                      R"({"success":false,"message":"invalid session"})",
                      MIME(Application, Json));
        	return;
    	}

		if (!redis_ptr->exists(info_key)) {
			_redisPool -> releaseConnection(redis_ptr);
            response.send(Pistache::Http::Code::Not_Found,
                          R"({"success":false,"message":"Upload session not found"})",
                          MIME(Application, Json));
            return;
        }

		std::string temp_dir = redis_ptr -> hget(info_key, "temp_dir");

		if (temp_dir.empty()) {
			_redisPool -> releaseConnection(redis_ptr);
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"Corrupted session data"})",
                          MIME(Application, Json));
            return;
        }
		redis_ptr->expire(info_key, 3600);

		auto body = req.body();
		
		if (body.size() > CHUNK_SIZE + 1024) { // 允许一点余量
			response.send(Pistache::Http::Code::Bad_Request, "Chunk too large");
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

		// 写入临时文件
		//std::string chunk_path = temp_dir + "/chunk_" + chunk_index;
		
		//写入失败了怎么办？
		if (redis_ptr->sadd(chunks_key, chunk_index) == 1) {
			// 成功加入集合 → 说明是首次
			std::string chunk_path = temp_dir + "/chunk_" + chunk_index;
			std::ofstream ofs(chunk_path, std::ios::binary);
			ofs.write(body.data(), body.size());

			redis_ptr->expire(chunks_key, 3600);
			json res;
        	res["status"] = "ok";
			response.send(Pistache::Http::Code::Ok, res.dump(), MIME(Application, Json));
		}
		
		redis_ptr -> set(status_key, "upload", 3600);
		redis_ptr->expire(status_key, 3600);
	} catch (const std::exception& e) {
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"Server exception"})",
                      MIME(Application, Json));
    } catch (...) {
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"Unknown error"})",
                      MIME(Application, Json));
    }
	_redisPool -> releaseConnection(redis_ptr);
	//responseTime = std::chrono::system_clock::now();
}

void Api::uploadLargeFileFinish(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response) {
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try{
		auto body = req.body(); //filename md5 filesize;
		json j = json::parse(body);
		std::string md5 = j.value("md5","");
		std::string upload_id = j.value("upload_id","");

		std::string chunks_key = "upload:" + upload_id + ":chunks";
		std::string upload_user_key = md5 + upload_id + ":ID";
		std::string status_key = "upload:" + upload_id + ":status";
		
		redis_ptr -> set(status_key, "mergeing", 3600);

		auto& cookies = req.cookies();
		std::string user = "";
		if (!validateUploadSession(req, upload_user_key, redis_ptr, user)){
			response.send(Pistache::Http::Code::Bad_Request,
					R"({"success":false,"message":"invalid session"})",
					MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

		response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));

		// auto responseDuration = std::chrono::system_clock::now() - responseTime;
		// auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(responseDuration).count();
		// std::cout<<"response time: "<<ms<<std::endl;

		_pthreadPool -> submit([upload_id, user, this](){
			//auto startTime = std::chrono::system_clock::now();
			//sleep(1);
			mergeChunksAndUpload(upload_id, user);
			// auto endTime = std::chrono::system_clock::now();
			// auto workMS = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - responseTime).count();
			// auto threadMS = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
			// std::cout<<"work time: "<<workMS<<std::endl;
			// std::cout<<"thread time: "<<threadMS<<std::endl;
		});
	} catch(...){}
	_redisPool -> releaseConnection(redis_ptr);
}

void Api::queryFileURL(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try{
		auto body = req.body();
		json j = json::parse(body);

		std::string md5 = j.value("md5","");
		std::string upload_id = j.value("upload_id", "");

		std::string status_key = "upload:" + upload_id + ":status";
		std::string upload_user_key = md5 + upload_id + ":ID";

		auto& cookies = req.cookies();
		std::string user = "";
		if (!validateUploadSession(req, upload_user_key, redis_ptr, user)){
			response.send(Pistache::Http::Code::Bad_Request,
					R"({"success":false,"message":"invalid session"})",
					MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}
		
		std::string upload_status = redis_ptr -> get(status_key);
		
		if (upload_status != "finish") { // 说明合并并上传文件系统没有完成
			if (upload_status != "mergeing") { // 说明 合并并上传文件系统 没有被调用
				response.send(Pistache::Http::Code::Ok,
					R"({"success":false,"error":"invalid merging"})",
					MIME(Application, Json));
				_redisPool -> releaseConnection(redis_ptr);
				return;
			}
		}

		std::string URL = redis_ptr -> get(md5);
		if (URL != "") {
			URL = "https://goodfloat.cloud/" + URL;
		}
		redis_ptr -> expire(md5, 3600);
		json response_json = {{"url", URL}};

		response.headers().add<Pistache::Http::Header::ContentType>(
			Pistache::Http::Mime::MediaType("application/json"));
    	response.send(Pistache::Http::Code::Ok, response_json.dump());
	}
	catch (const std::exception& e) {
		MY_LOG_ERROR("Error in queryUserFiles: ", e.what());
        response.send(Pistache::Http::Code::Internal_Server_Error, "Server error");
	}
	_redisPool->releaseConnection(redis_ptr);
}

void Api::queryUserFiles(const Pistache::Http::Request& req, Pistache::Http::ResponseWriter response){
	try{
		auto& cookies = req.cookies();
		std::string sessionId = "";
		if (cookies.has("session")) {
			sessionId = cookies.get("session").value;
			// 验证 sessionId 是否有效...
		} else {
			MY_LOG_ERROR("queryUserFiles invalid session: ", sessionId);
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
			return;
		}
		std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
		std::string uses_key = "user:" + sessionId;
		std::string username = redis_ptr -> get(uses_key);
		redis_ptr -> expire(uses_key, 600);
		_redisPool->releaseConnection(redis_ptr);
		
		json array = json::array();

		std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();

		mysql_ptr -> queryUserFiles(username, array);
		_mysqlPool -> releaseConnection(mysql_ptr);

		// 转为字符串并返回
        std::string jsonString = array.dump();
		
		// 3. 返回JSON给前端（前端loadFiles()可直接解析）
		response.headers().add<Pistache::Http::Header::ContentType>(
			Pistache::Http::Mime::MediaType("application/json"));
    	response.send(Pistache::Http::Code::Ok, jsonString);
	}
	catch (const std::exception& e) {
		//std::cerr << "Error in queryUserFiles: " << e.what() << std::endl;
		MY_LOG_ERROR("Error in queryUserFiles: ", e.what());
        response.send(Pistache::Http::Code::Internal_Server_Error, "Server error");
	}
}

// ==================Delete / deleteFiles , 异步删除比较好，这里就不做了，逻辑和大文件上传一样的================
void Api::deleteCheck(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	bool success = false;
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	std::shared_ptr<Mysql> mysql_ptr = _mysqlPool->getConnection();
	try {
        auto idOpt   = req.query().get("id");
		if (!idOpt) {
            response.send(Pistache::Http::Code::Bad_Request,
                R"({"success":false,"message":"Missing user or id"})",
                MIME(Application, Json));
            return;
        }
        std::string md5  = idOpt.value();

		auto& cookies = req.cookies();
		std::string sessionId = "";
		if (cookies.has("session")) {
			sessionId = cookies.get("session").value;
			// 验证 sessionId 是否有效...
		} else {
			//std::cerr<<"[UploadCheck ERROR] "<<"invalid session"<<std::endl;
			MY_LOG_ERROR("deleteCheck invalid session: ", sessionId);
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
		}
		std::string uses_key = "user:" + sessionId;
		std::string user = redis_ptr -> get(uses_key);
		redis_ptr -> expire(uses_key, 600);
		
		if (user.empty() || md5.empty()) {
            response.send(Pistache::Http::Code::Bad_Request, "Missing user or id");
            return;
        }

		if (mysql_ptr -> deleteUserFile(user, md5)) { // 先给用户删除
			std::cout << "[MySQL INFO] Successed user: "<<user<<" deleted file: "<< md5<< std::endl;
			//MY_LOG_INFO("MySQL user", user, " Delete file: ", md5, "Succeeded");
		}
		if (mysql_ptr -> updateCount(md5, -1)) { // 给文件 count -1;
			//std::cerr<<"user: "<< user <<" delete file"<<std::endl;
			//MY_LOG_INFO("MySQL update file", md5, " Succeeded");
		}
		int count = 0;
		std::string url;
		if (mysql_ptr -> getCount(md5, count, url)) {
			std::cout << "[MySQL INFO] Successed file: "<<md5<<" update count: "<<count<<std::endl;
			//MY_LOG_INFO("MySQL Update file: ", md5, "count: ",count, " Successed");
		 } //else {
		// 	std::cout << "[MySQL INFO] Failed file: "<<md5<<" update count: "<<count<<std::endl;
		// }
		if (count == 0) { // 已经没有用户需要这个文件
			redis_ptr -> del(md5);

			// _pthreadPool -> submit([this, &url](){
			// 	this->deleteFiles(url);
			// });

			this->deleteFiles(url);

			if (mysql_ptr -> deleteSysFile(md5)) {
				std::cerr<<"[MySQL INFO] "<<"Successed user: "<<user<<" delete file: "<<md5<<std::endl;
			} // 从 file_info 中删除
			//std::cerr<<"[MySQL INFO] "<<"Successed user: "<<user<<" delete file: "<<md5<<std::endl;
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
	_redisPool -> releaseConnection(redis_ptr);
	_mysqlPool -> releaseConnection(mysql_ptr);
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
		std::cout << "[Fdfs INFO] Successfully deleted FastDFS file: group= " 
              << group_name << "\", file=\"" << remote_file << "\"" << std::endl;
		//MY_LOG_INFO("Fdfs Deleted file: group= ", group_name , "/file=", remote_file, "Succeeded");
	} else {
		// std::cerr << "[Fdfs ERROR] Failed to delete FastDFS file: group=\"" 
        //       << group_name << "\", file=\"" << remote_file << "\"" << std::endl;
		MY_LOG_ERROR("Fdfs Delete file: group= ", group_name, "file = ", remote_file, "Failed");
		return;  // 跳过redis
	}

	_fdfsPool -> releaseConnection(connFdfs);
}


// ====================== Merge =======================
void Api::mergeChunksAndUpload(const std::string& upload_id, const std::string& user){
	std::shared_ptr<FdfsClient> fdfs_ptr = _fdfsPool -> getConnection();
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	std::shared_ptr<Mysql> mysql_ptr = _mysqlPool -> getConnection();

	try {
		std::string info_key   = "upload:" + upload_id + ":info";
		std::string status_key = "upload:" + upload_id + ":status";
		std::string chunks_key = "upload:" + upload_id + ":chunks";

		std::string temp_dir = redis_ptr -> hget(info_key, "temp_dir");
		int total_chunks = std::stoi(redis_ptr -> hget(info_key, "total_chunks"));


		if (total_chunks != redis_ptr -> scard(chunks_key)){ //数量相同默认上传成功
			redis_ptr -> set(status_key, "uploadfail", 3600);
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

        // 2. 拼接文件
        std::string temp_path = temp_dir + "/__final__.tmp";
        {
            std::ofstream ofs(temp_path, std::ios::binary);
            for (int i = 0; i < total_chunks; ++i) {
                std::ifstream ifs(temp_dir + "/chunk_" + std::to_string(i), std::ios::binary);
                if (!ifs) throw std::runtime_error("Missing chunk " + std::to_string(i));
                ofs << ifs.rdbuf();
            }
        }

        // 3. 上传 FastDFS
        char file_id[256] = {0};
		
		std::string file_ext = redis_ptr -> hget(info_key, "file_ext");
		std::string fdfs_path = fdfs_ptr -> upload_file_to_fastdfs(temp_path.c_str(), file_ext.c_str());
		if (!mysql_ptr -> beginTransaction()) {
			// 事务开启失败，需要清理 FastDFS 上已上传的文件
			size_t firstSlash = fdfs_path.find('/');
			std::string group_name = fdfs_path.substr(0,firstSlash);
			std::string remote_file = fdfs_path.substr(firstSlash+1);
			fdfs_ptr -> delete_file_from_fastdfs(group_name, remote_file);
			_fdfsPool -> releaseConnection(fdfs_ptr);
			_redisPool -> releaseConnection(redis_ptr);
			_mysqlPool->releaseConnection(mysql_ptr);
			return;
		}
// ================= 下面只是能用， 细节还需打磨 ========================
		if (fdfs_path.empty()) {
			_fdfsPool -> releaseConnection(fdfs_ptr);
           	// response.send(Pistache::Http::Code::Bad_Request,
            //     R"({"success":false,"message":"upload to fastdfs false"})",
            //     MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			_mysqlPool->releaseConnection(mysql_ptr);
			std::cerr << "上传失败, 路径为空" << std::endl;
            return;
        }

		//delete tem file
		std::filesystem::remove(temp_path);
		std::filesystem::remove_all(temp_dir);  // 递归删除整个目录树！
		_fdfsPool -> releaseConnection(fdfs_ptr);

		std::string md5 = redis_ptr -> hget(info_key, "md5");
		std::string filename = redis_ptr -> hget(info_key, "filename");

		bool db_success = false;
		if (!(mysql_ptr -> insertUserFile(md5, user, filename))){
			//std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<user<<"file: "<<filename<<"to user_file_list"<<std::endl;
		}
		if (!(mysql_ptr -> insertFileInfo(md5, fdfs_path, file_ext))){
			//std::cerr<<"[MySQL ERROE] Failed Insert file: "<<filename<<"to file_info" <<std::endl;
		}
		db_success = true;

		if (!(mysql_ptr -> commit())) {
			db_success = false;
			//std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
		}
		if (!db_success) {
			mysql_ptr->rollback();
			//std::cerr << "[MySQL INFO] Transaction rolled back." << std::endl;
			//std::string url = fastdfs_path;
			deleteFiles(fdfs_path); 
			_mysqlPool -> releaseConnection(mysql_ptr);
			// response.send(Pistache::Http::Code::Internal_Server_Error,
			// 	R"({"success":false,"message":"数据库操作失败或事务提交失败，文件已回滚"})",
			// 	MIME(Application, Json));
		}

		_mysqlPool -> releaseConnection(mysql_ptr);

		if (!(redis_ptr -> set(md5, fdfs_path, 3600))) {
			_redisPool -> releaseConnection(redis_ptr);
			// response.send(Pistache::Http::Code::Bad_Request,
            //  R"({"success":false,"message":"请先调用 /upload/check"})",
            //  MIME(Application, Json));
             return;
		}
		//_redisPool -> releaseConnection(redis_ptr);


    } catch (const std::exception& e) {
        MY_LOG_ERROR("", e.what());
    }

    // 5. 清理
    try {
		//不用清理等他自动过期，更新redis状态才对
		
		std::string status_key = "upload:" + upload_id + ":status";
		redis_ptr -> set(status_key, "finish", 3600);
		_redisPool -> releaseConnection(redis_ptr);
    } catch (...) {}
}

