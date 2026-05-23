#include "upload_handler.h"

#include <fstream>
#include <iostream>

#include <nlohmann/json.hpp>

#include "../common/session_auth.h"
#include "../common/fdfs_ops.h"
#include "../../utils/utils.h"
#include "../../utils/file.hpp"
#include "../../utils/asyncLogger.h"

UploadHandler::UploadHandler()
    : _mysqlPool(MySQLConnPool::getInstance()),
      _redisPool(RedisConnPool::getInstance()),
      _fdfsPool(FdfsConnPool::getInstance()),
      _pthreadPool(uploadThreadPool::getInstance()) {}
// =========== POST / up and check
void UploadHandler::uploadCheck(const  Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	std::cout<<"uploadCheck start"<<std::endl;
	std::shared_ptr<Mysql> mysql_ptr = _mysqlPool -> getConnection();
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try{
		auto body = req.body(); //filename md5 filesize;
		nlohmann::json j = nlohmann::json::parse(body);
		std::string filename = j.value("filename","");
		std::string md5 = j.value("md5","");

		std::string user = "";
		if (!session_auth::validateUploadSession(req, "", redis_ptr, user)){
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
void UploadHandler::upload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
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
		if (!session_auth::validateUploadSession(req, "", redis_ptr, user)){
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
			fdfs_ops::deleteFile(_fdfsPool, fastdfs_path); 
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
		nlohmann::json responseJson = {
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
void UploadHandler::largeInit(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection(); 
	try {
		std::string user = "";
		if (!session_auth::validateUploadSession(req, "", redis_ptr, user)) {
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session"})",
                    MIME(Application, Json));
			_redisPool -> releaseConnection(redis_ptr);
			return;
		}

		auto body = req.body();
		nlohmann::json j = nlohmann::json::parse(body);
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

void UploadHandler::largeFileUpload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
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
		if (!session_auth::validateUploadSession(req, upload_user_key, redis_ptr, user)) {
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
			nlohmann::json res;
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

void UploadHandler::uploadLargeFileFinish(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response) {
	std::shared_ptr<Redis> redis_ptr = _redisPool -> getConnection();
	try{
		auto body = req.body(); //filename md5 filesize;
		nlohmann::json j = nlohmann::json::parse(body);
		std::string md5 = j.value("md5","");
		std::string upload_id = j.value("upload_id","");

		std::string chunks_key = "upload:" + upload_id + ":chunks";
		std::string upload_user_key = md5 + upload_id + ":ID";
		std::string status_key = "upload:" + upload_id + ":status";
		
		redis_ptr -> set(status_key, "mergeing", 3600);

		auto& cookies = req.cookies();
		std::string user = "";
		if (!session_auth::validateUploadSession(req, upload_user_key, redis_ptr, user)){
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

// ====================== Merge =======================
void UploadHandler::mergeChunksAndUpload(const std::string& upload_id, const std::string& user){
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
			fdfs_ptr -> delete_file_from_fastdfs(fdfs_path);
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
			_mysqlPool -> releaseConnection(mysql_ptr);
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
			fdfs_ops::deleteFile(_fdfsPool, fdfs_path); 
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
