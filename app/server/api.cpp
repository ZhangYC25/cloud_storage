#include <iostream>
#include "api.h"

std::shared_ptr<Api> Api::_apiInstance = nullptr;
std::mutex Api::_instanceMtx;

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

void Api::destroyInstance(){
	std::lock_guard<std::mutex> lock(_instanceMtx);
    if (_apiInstance) {
        _apiInstance.reset();
    }
}

void Api::shutdown() {
    this->running.store(false); 
    this->_cv.notify_all();
}

Api::Api(){ 
	_mysqlPool = MySQLConnPool::getInstance();
	_fdfsPool = FdfsConnPool::getInstance();
	_pthreadPool = uploadThreadPool::getInstance();

	_pthreadPool -> submit([this](){
		this -> healthCheckLoop();
	});
}

void Api::healthCheckLoop() {
    std::this_thread::sleep_for(std::chrono::minutes(1));

    while (running.load()) {
        MY_LOG_INFO("Starting daily consistency check...");
        this->runConsistencyCheck(); 

        std::unique_lock<std::mutex> lock(_mtx);
        bool stopped = _cv.wait_for(lock, std::chrono::hours(24), [this] {
            return !this->running.load();
        });

        if (stopped || !running.load()) {
            break;
        }
    }
    MY_LOG_INFO("Health Check task exited safely.");
}

void Api::runConsistencyCheck() {
    MY_LOG_INFO("=== [Health Check] Task Started ===");
    
    int offset = 0;
    const int batch_size = 100;
    int total_checked = 0;
    std::vector<std::string> corrupted_md5s;

    auto mysql_ptr = _mysqlPool->getConnection();
    auto fdfs_ptr = _fdfsPool->getConnection();

    while (true) {
        std::vector<FileRecord> batch = mysql_ptr->getFileRecordsBatch(batch_size, offset);
        if (batch.empty()) break;

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

Api::~Api() {}

void Api::setupRoutes(){
	using namespace Pistache::Rest;
    using Pistache::Http::ResponseWriter;

    Routes::Post(router, "/api/register", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _auth.registerUser(req, std::move(response));
            return Route::Result::Ok;
        }
    );

	Routes::Post(router, "/api/email", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _auth.registerEmail(req, std::move(response));
            return Route::Result::Ok;
        }
    );

    Routes::Post(router, "/api/login", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _auth.loginUser(req, std::move(response));
            return Route::Result::Ok;
        }
    );
    
    Routes::Post(router, "/api/upload/file", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _upload.upload(req, std::move(response));
            return Route::Result::Ok;
        }
    );
    
    Routes::Post(router, "/api/upload/check", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _upload.uploadCheck(req, std::move(response));
            return Route::Result::Ok;
        }
    );

	Routes::Get(router, "/api/files", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _file.queryUserFiles(req, std::move(response));
            return Route::Result::Ok;
        }
    );

	Routes::Delete(router, "/api/delete", 
        [this](const Request& req, ResponseWriter response) -> Route::Result {
            _file.deleteCheck(req, std::move(response));
            return Route::Result::Ok;
        }
    );

	Routes::Post(router, "/api/upload/init", 
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			_upload.largeInit(req, std::move(response));
			return Route::Result::Ok;
		}
	);

	Routes::Post(router, "/api/upload/chunk",
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			_upload.largeFileUpload(req, std::move(response));
			return Route::Result::Ok;
		}
	);

	Routes::Post(router, "/api/upload/finish",
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			_upload.uploadLargeFileFinish(req, std::move(response));
			return Route::Result::Ok;
		}
	);

	Routes::Post(router, "/api/upload/query",
		[this](const Request& req, ResponseWriter response) -> Route::Result{
			_file.queryFileURL(req, std::move(response));
			return Route::Result::Ok;
		});
}
