#include "upload_handler.h"

#include <fstream>
#include <iostream>

#include <nlohmann/json.hpp>

#include "../session.h"
#include "../common/fdfs_ops.h"
#include "../../utils/utils.h"
#include "../../utils/file.hpp"
#include "../../utils/asyncLogger.h"

namespace {

struct MysqlGuard {
    MySQLConnPool* pool = nullptr;
    std::shared_ptr<Mysql> conn;

    MysqlGuard(MySQLConnPool* p, std::shared_ptr<Mysql> c) : pool(p), conn(std::move(c)) {}
    ~MysqlGuard() {
        if (pool && conn) {
            pool->releaseConnection(conn);
        }
    }

    MysqlGuard(const MysqlGuard&) = delete;
    MysqlGuard& operator=(const MysqlGuard&) = delete;
};

struct RedisGuard {
    RedisConnPool* pool = nullptr;
    std::shared_ptr<Redis> conn;

    RedisGuard(RedisConnPool* p, std::shared_ptr<Redis> c) : pool(p), conn(std::move(c)) {}
    ~RedisGuard() {
        if (pool && conn) {
            pool->releaseConnection(conn);
        }
    }

    RedisGuard(const RedisGuard&) = delete;
    RedisGuard& operator=(const RedisGuard&) = delete;
};

struct FdfsGuard {
    FdfsConnPool* pool = nullptr;
    std::shared_ptr<FdfsClient> conn;

    FdfsGuard(FdfsConnPool* p, std::shared_ptr<FdfsClient> c) : pool(p), conn(std::move(c)) {}
    ~FdfsGuard() {
        if (pool && conn) {
            pool->releaseConnection(conn);
        }
    }

    FdfsGuard(const FdfsGuard&) = delete;
    FdfsGuard& operator=(const FdfsGuard&) = delete;
};

}  // namespace

UploadHandler::UploadHandler()
    : _mysqlPool(MySQLConnPool::getInstance()),
      _redisPool(RedisConnPool::getInstance()),
      _fdfsPool(FdfsConnPool::getInstance()),
      _pthreadPool(uploadThreadPool::getInstance()) {}
// =========== POST / up and check
void UploadHandler::uploadCheck(const  Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	std::cout<<"uploadCheck start"<<std::endl;
	MysqlGuard mysql{_mysqlPool, _mysqlPool->getConnection()};
	RedisGuard redis{_redisPool, _redisPool->getConnection()};
	try{
		auto body = req.body(); //filename md5 filesize;
		nlohmann::json j = nlohmann::json::parse(body);
		std::string filename = j.value("filename","");
		std::string md5 = j.value("md5","");

		std::string user = "";
		if (!Session::validateUploadSession(req, "", redis.conn, user)){
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
			return;
		}

		if (mysql.conn -> isInUserList(md5, user)) { // 先查 userfile 命中的话其他根本不用查。
			std::cerr<<"[UploadCheck INFO] "<<"user: "<<user<<" already owned File"<<std::endl;
			//MY_LOG_INFO("UploadCheck user: ", user, "already owned File");
				response.send(Pistache::Http::Code::Ok,
                    R"({"success":true,"status":"already_owned"})",
                    MIME(Application, Json));
		} else if (mysql.conn -> isInMySQL(md5)) { //能找到这里说明 用户肯定没有这个文件 在查 系统表有没有这个文件，有的话
			std::string md5_key = "md5:" + md5;
			if (redis.conn->get(md5_key)== "") { // 在查 redis 有没有这个文件，没有就重新插进去
				int count = 0;
				std::string url = "";
				mysql.conn -> getCount(md5, count, url);
				redis.conn -> set(md5_key,url, 3600);
			}
			// 秒传，count + 1
			if (!(mysql.conn -> beginTransaction())) {
					response.send(Pistache::Http::Code::Internal_Server_Error,
						R"({"success":false,"message":"数据库事务开启失败"})",
						MIME(Application, Json));
					return;
				}

				if (!(mysql.conn -> insertUserFile(md5, user, filename))) {
					// std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<
					// user<<"file: "<<filename<<"to user_file_list"<<std::endl;
					//MY_LOG_ERROR("MySQL Failed Insert file for user: ")
				}
				if (!(mysql.conn -> updateCount(md5, 1))){
					//std::cerr<<"[MySQL ERROR]  Failed Update count for file: "<<filename<<std::endl;
				}
				bool db_success = true;
				if (!(mysql.conn -> commit())) {
					db_success = false;
					//std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
				}
				if (!db_success) {
					mysql.conn->rollback();
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
	}catch (const std::exception& e) {
			response.send(Pistache::Http::Code::Bad_Request, R"({"error": "invalid json"})");
		}
}

// ================= POST / upload 
void UploadHandler::upload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	RedisGuard redis{_redisPool, _redisPool->getConnection()};
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
		
		std::string user = "";
		if (!Session::validateUploadSession(req, "", redis.conn, user)){
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session!"})",
                    MIME(Application, Json));
			return;
		}

		auto body = req.body();

		MysqlGuard mysql{_mysqlPool, _mysqlPool->getConnection()};

		if (!mysql.conn->beginTransaction()) {
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"数据库事务开启失败"})",
				MIME(Application, Json));
			return;
		}

		const char* ext = strrchr(file_name.c_str(),'.');
		const char* file_ext = ext ? ext + 1 : "";

		std::string fastdfs_path;
		{
			FdfsGuard fdfs{_fdfsPool, _fdfsPool->getConnection()};
			std::string temp_path = fdfs.conn -> create_temp_file(body);
			if (temp_path.empty()) {
				mysql.conn->rollback();
				response.send(Pistache::Http::Code::Bad_Request,
					R"({"success":false,"message":"/write /tmp/ false"})",
					MIME(Application, Json));
				return;
			}
			fastdfs_path = fdfs.conn -> upload_file_to_fastdfs(temp_path.c_str(), file_ext);
			if (fastdfs_path.empty()) {
				mysql.conn->rollback();
				response.send(Pistache::Http::Code::Bad_Request,
					R"({"success":false,"message":"upload to fastdfs false"})",
					MIME(Application, Json));
				return;
			}
			std::filesystem::remove(temp_path);
		}

		bool db_success = false;
		if (!(mysql.conn -> insertUserFile(md5, user, file_name))){
			//std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<user<<"file: "<<filename<<"to user_file_list"<<std::endl;
		}
		if (!(mysql.conn -> insertFileInfo(md5, fastdfs_path, file_ext))){
			//std::cerr<<"[MySQL ERROE] Failed Insert file: "<<filename<<"to file_info" <<std::endl;
		}
		db_success = true;
		

		if (!(mysql.conn -> commit())) {
			db_success = false;
			//std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
		}
		if (!db_success) {
			mysql.conn->rollback();
			//std::cerr << "[MySQL INFO] Transaction rolled back." << std::endl;
			fdfs_ops::deleteFile(_fdfsPool, fastdfs_path); 
			response.send(Pistache::Http::Code::Internal_Server_Error,
				R"({"success":false,"message":"数据库操作失败或事务提交失败，文件已回滚"})",
				MIME(Application, Json));
			return;
		}

		if (!(redis.conn -> set(md5, fastdfs_path, 3600))) {
			response.send(Pistache::Http::Code::Bad_Request,
             R"({"success":false,"message":"请先调用 /upload/check"})",
             MIME(Application, Json));
             return;
		}

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
	RedisGuard redis{_redisPool, _redisPool->getConnection()}; 
	try {
		std::string user = "";
		if (!Session::validateUploadSession(req, "", redis.conn, user)) {
			response.send(Pistache::Http::Code::Bad_Request,
                    R"({"success":false,"message":"invalid session"})",
                    MIME(Application, Json));
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
        	return;
    	}

		std::string upload_id = generate_upload_id();
		std::string temp_dir = TEMP_BASE_DIR + "/" + upload_id;
		std::filesystem::create_directories(temp_dir);

		std::string info_key = "upload:" + upload_id + ":info";
		std::string status_key = "upload:" + upload_id + ":status";
		std::string upload_user_key = md5 + upload_id + ":ID";

		redis.conn -> set(upload_user_key, user, 3600);
		redis.conn -> set(status_key, "initial", 3600);

		if (redis.conn -> hset(info_key, "filename", filename) &&
        	redis.conn -> hset(info_key, "temp_dir", temp_dir) &&
        	redis.conn -> hset(info_key, "total_chunks", std::to_string(total_chunks)) &&
        	redis.conn -> hset(info_key, "md5", md5) &&
			redis.conn -> hset(info_key, "file_ext", file_ext)) {
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
}

//std::chrono::_V2::system_clock::time_point responseTime;

void UploadHandler::largeFileUpload(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response){
	RedisGuard redis{_redisPool, _redisPool->getConnection()};
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
		if (!Session::validateUploadSession(req, upload_user_key, redis.conn, user)) {
        	response.send(Pistache::Http::Code::Unauthorized,
                      R"({"success":false,"message":"invalid session"})",
                      MIME(Application, Json));
        	return;
    	}

		if (!redis.conn->exists(info_key)) {
            response.send(Pistache::Http::Code::Not_Found,
                          R"({"success":false,"message":"Upload session not found"})",
                          MIME(Application, Json));
            return;
        }

		std::string temp_dir = redis.conn -> hget(info_key, "temp_dir");

		if (temp_dir.empty()) {
            response.send(Pistache::Http::Code::Internal_Server_Error,
                          R"({"success":false,"message":"Corrupted session data"})",
                          MIME(Application, Json));
            return;
        }
		redis.conn->expire(info_key, 3600);

		auto body = req.body();
		
		if (body.size() > CHUNK_SIZE + 1024) { // 允许一点余量
			response.send(Pistache::Http::Code::Bad_Request, "Chunk too large");
			return;
		}

		// 写入临时文件
		//std::string chunk_path = temp_dir + "/chunk_" + chunk_index;
		
		//写入失败了怎么办？
		if (redis.conn->sadd(chunks_key, chunk_index) == 1) {
			// 成功加入集合 → 说明是首次
			std::string chunk_path = temp_dir + "/chunk_" + chunk_index;
			std::ofstream ofs(chunk_path, std::ios::binary);
			ofs.write(body.data(), body.size());

			redis.conn->expire(chunks_key, 3600);
			nlohmann::json res;
        	res["status"] = "ok";
			response.send(Pistache::Http::Code::Ok, res.dump(), MIME(Application, Json));
		}
		
		redis.conn -> set(status_key, "upload", 3600);
		redis.conn->expire(status_key, 3600);
	} catch (const std::exception& e) {
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"Server exception"})",
                      MIME(Application, Json));
    } catch (...) {
        response.send(Pistache::Http::Code::Internal_Server_Error,
                      R"({"success":false,"message":"Unknown error"})",
                      MIME(Application, Json));
    }
	//responseTime = std::chrono::system_clock::now();
}

void UploadHandler::uploadLargeFileFinish(const Pistache::Rest::Request& req, Pistache::Http::ResponseWriter response) {
	RedisGuard redis{_redisPool, _redisPool->getConnection()};
	try {
		auto body = req.body();
		nlohmann::json j = nlohmann::json::parse(body);
		std::string md5 = j.value("md5", "");
		std::string upload_id = j.value("upload_id", "");

		if (md5.empty() || upload_id.empty()) {
			response.send(Pistache::Http::Code::Bad_Request,
				R"({"success":false,"message":"missing md5 or upload_id"})",
				MIME(Application, Json));
			return;
		}

		std::string info_key = "upload:" + upload_id + ":info";
		std::string status_key = "upload:" + upload_id + ":status";
		std::string chunks_key = "upload:" + upload_id + ":chunks";
		std::string upload_user_key = md5 + upload_id + ":ID";

		std::string user = "";
		if (!Session::validateUploadSession(req, upload_user_key, redis.conn, user)) {
			response.send(Pistache::Http::Code::Bad_Request,
				R"({"success":false,"message":"invalid session"})",
				MIME(Application, Json));
			return;
		}

		if (!redis.conn->exists(info_key)) {
			response.send(Pistache::Http::Code::Not_Found,
				R"({"success":false,"message":"upload session not found"})",
				MIME(Application, Json));
			return;
		}

		std::string stored_md5 = redis.conn->hget(info_key, "md5");
		if (!stored_md5.empty() && stored_md5 != md5) {
			response.send(Pistache::Http::Code::Bad_Request,
				R"({"success":false,"message":"md5 mismatch"})",
				MIME(Application, Json));
			return;
		}

		std::string current_status = redis.conn->get(status_key);
		if (current_status == "finish") {
			nlohmann::json res;
			res["success"] = true;
			res["status"] = "finish";
			std::string url = redis.conn->get(md5);
			if (!url.empty()) {
				res["url"] = "https://goodfloat.cloud/" + url;
			}
			response.send(Pistache::Http::Code::Ok, res.dump(), MIME(Application, Json));
			return;
		}
		if (current_status == "mergeing") {
			response.send(Pistache::Http::Code::Ok,
				R"({"success":true,"status":"mergeing"})",
				MIME(Application, Json));
			return;
		}
		if (current_status == "uploadfail") {
			response.send(Pistache::Http::Code::Ok,
				R"({"success":false,"message":"文件合并失败，请重新上传"})",
				MIME(Application, Json));
			return;
		}

		int total_chunks = std::stoi(redis.conn->hget(info_key, "total_chunks"));
		if (total_chunks != redis.conn->scard(chunks_key)) {
			response.send(Pistache::Http::Code::Bad_Request,
				R"({"success":false,"message":"分片不完整，无法合并"})",
				MIME(Application, Json));
			return;
		}

		redis.conn->set(status_key, "mergeing", 3600);

		_pthreadPool->submit([upload_id, user, this]() {
			mergeChunksAndUpload(upload_id, user);
		});

		response.send(Pistache::Http::Code::Ok,
			R"({"success":true,"status":"mergeing"})",
			MIME(Application, Json));
	} catch (const nlohmann::json::parse_error&) {
		response.send(Pistache::Http::Code::Bad_Request,
			R"({"success":false,"message":"invalid json"})",
			MIME(Application, Json));
	} catch (const std::exception& e) {
		MY_LOG_ERROR("uploadLargeFileFinish failed: ", e.what());
		response.send(Pistache::Http::Code::Internal_Server_Error,
			R"({"success":false,"message":"server error"})",
			MIME(Application, Json));
	}
}

// ====================== Merge =======================
void UploadHandler::mergeChunksAndUpload(const std::string& upload_id, const std::string& user){
	FdfsGuard fdfs{_fdfsPool, _fdfsPool->getConnection()};
	RedisGuard redis{_redisPool, _redisPool->getConnection()};
	MysqlGuard mysql{_mysqlPool, _mysqlPool->getConnection()};

	std::string status_key = "upload:" + upload_id + ":status";

	try {
		std::string info_key   = "upload:" + upload_id + ":info";
		std::string chunks_key = "upload:" + upload_id + ":chunks";

		std::string temp_dir = redis.conn -> hget(info_key, "temp_dir");
		int total_chunks = std::stoi(redis.conn -> hget(info_key, "total_chunks"));


		if (total_chunks != redis.conn -> scard(chunks_key)){ //数量相同默认上传成功
			redis.conn -> set(status_key, "uploadfail", 3600);
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
		std::string file_ext = redis.conn -> hget(info_key, "file_ext");
		std::string fdfs_path = fdfs.conn -> upload_file_to_fastdfs(temp_path.c_str(), file_ext.c_str());
		if (fdfs_path.empty()) {
			redis.conn -> set(status_key, "uploadfail", 3600);
			std::cerr << "上传失败, 路径为空" << std::endl;
            return;
        }

		if (!mysql.conn -> beginTransaction()) {
			fdfs.conn -> delete_file_from_fastdfs(fdfs_path);
			redis.conn -> set(status_key, "uploadfail", 3600);
			return;
		}

		std::filesystem::remove(temp_path);
		std::filesystem::remove_all(temp_dir);

		std::string md5 = redis.conn -> hget(info_key, "md5");
		std::string filename = redis.conn -> hget(info_key, "filename");

		bool db_success = false;
		if (!(mysql.conn -> insertUserFile(md5, user, filename))){
			//std::cerr<<"[MySQL ERROR]  Failed Insert file for user: "<<user<<"file: "<<filename<<"to user_file_list"<<std::endl;
		}
		if (!(mysql.conn -> insertFileInfo(md5, fdfs_path, file_ext))){
			//std::cerr<<"[MySQL ERROE] Failed Insert file: "<<filename<<"to file_info" <<std::endl;
		}
		db_success = true;

		if (!(mysql.conn -> commit())) {
			db_success = false;
			//std::cerr << "[MySQL ERROR] Failed to commit transaction." << std::endl;
		}
		if (!db_success) {
			mysql.conn->rollback();
			fdfs_ops::deleteFile(_fdfsPool, fdfs_path);
			redis.conn -> set(status_key, "uploadfail", 3600);
			return;
		}

		if (!(redis.conn -> set(md5, fdfs_path, 3600))) {
			redis.conn -> set(status_key, "uploadfail", 3600);
			return;
		}

		redis.conn -> set(status_key, "finish", 3600);

    } catch (const std::exception& e) {
        MY_LOG_ERROR("mergeChunksAndUpload failed: ", e.what());
		try {
			redis.conn -> set(status_key, "uploadfail", 3600);
		} catch (...) {}
    }
}
