#include "fdfsClient.h"

#include <cerrno>
#include <cstring>

FdfsClient::FdfsClient():conf_path("/etc/fdfs/client.conf"), pTrackerServer(nullptr){
    createConnection();
}

FdfsClient::~FdfsClient(){
    closeConnection();
}

bool FdfsClient::createConnection() {
    closeConnection(); // 先关旧的

    pTrackerServer = tracker_get_connection();
    if (pTrackerServer == nullptr || pTrackerServer->sock < 0) {
        //std::cerr << "创建Tracker连接失败!" << std::endl;
        MY_LOG_ERROR("Fdfs Create Tracker failed");
        return false;
    }

    // 校验连接有效性
    if (pTrackerServer == nullptr) {
        closeConnection();
        //std::cerr << "Tracker连接无效!" << std::endl;
        MY_LOG_ERROR("Fdfs Create Tracker invalid");
        return false;
    }
    return true;
}
void FdfsClient::closeConnection() {
    if (pTrackerServer != nullptr) {
        tracker_close_connection_ex(pTrackerServer, true);
        pTrackerServer = nullptr;
    }
}

ConnectionInfo* FdfsClient::getPtrackerServer(){return pTrackerServer;};

bool FdfsClient::ensureConnection() {
    if (pTrackerServer != nullptr && pTrackerServer->sock >= 0) {
        return true;
    }
    return createConnection();
}

std::string FdfsClient::upload_file_to_fastdfs(const char* local_path, const char* file_ext){
    ConnectionInfo storageServer;
	memset(&storageServer, 0, sizeof(storageServer));
	char group_name[FDFS_GROUP_NAME_MAX_LEN + 1] = {0};
	int store_path_index = 0;

    if (pTrackerServer == NULL || pTrackerServer->sock < 0) {
        //fprintf(stderr, "[Fdfs ERROR] tracker server connection is invalid\n");
        MY_LOG_ERROR("Fdfs tracker server connection is invalid");
    }
	int result = tracker_query_storage_store(pTrackerServer, &storageServer,
			group_name, &store_path_index);
	if (result != 0) {
		closeConnection();
		MY_LOG_ERROR("Fdfs tracker_query_storage_store failed, code=", result);
		return "";
	}

	char file_id[256] = {0};
	//提取文件扩展名
	//const char* ext = strrchr(local_path,'.');
	//const char* file_ext = ext?ext+1:"";
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
    //std::cout<<group_name<<std::endl;
    if (result == 0) {
        std::cout << "[Fdfs INFO] Successed upload FastDFS file: group=\"" 
              << group_name <<", file= "<< std::string(file_id) << std::endl;
        return std::string(group_name) + "/" + std::string(file_id);
    }
    return "";
}

// 新版本：支持零拷贝写入
std::string FdfsClient::create_temp_file(std::string_view data) {
    char temp_template[] = "/tmp/fastdfs_upload_XXXXXX";
    int fd = mkstemp(temp_template);
    if (fd == -1) {
        MY_LOG_ERROR("mkstemp failed: ", strerror(errno));
        return "";
    }
    size_t total = 0;
    while (total < data.size()) {
        ssize_t n = write(fd, data.data() + total, data.size() - total);
        if (n <= 0) {
            MY_LOG_ERROR("write failed: ", strerror(errno));
            close(fd);
            unlink(temp_template);
            return "";
        }
        total += n;
    }
    close(fd);
    return std::string(temp_template);
}

bool FdfsClient::delete_file_from_fastdfs(const std::string& file_id){
    if (file_id.empty()) {
        MY_LOG_ERROR("Fdfs delete skipped: empty file_id");
        return false;
    }

    if (!ensureConnection()) {
        MY_LOG_ERROR("Fdfs delete failed: tracker connection unavailable");
        return false;
    }

    int result = storage_delete_file1(pTrackerServer, nullptr, file_id.c_str());
    if (result != 0) {
        MY_LOG_ERROR("Fdfs Delete file ", file_id, " failed, code=", result);
        if (result == ECONNREFUSED || result == ENOENT) {
            closeConnection();
        }
        return false;
    }
    return true;
}


bool FdfsClient::check_file_exists(const std::string& url) {
    // 1. 解析 URL (group1/M00/00/00/xxx.jpg -> group_name 和 remote_filename)
    size_t firstSlash = url.find('/');
    if (firstSlash == std::string::npos) return false;

    std::string group_name = url.substr(0, firstSlash);
    std::string remote_filename = url.substr(firstSlash + 1);

    // 2. 准备接收信息的结构体
    FDFSFileInfo file_info;
    memset(&file_info, 0, sizeof(file_info));

    int result = fdfs_get_file_info(group_name.c_str(), remote_filename.c_str(), &file_info);

    if (result == 0) {
        return true; 
    } else {
        return false;
    }
}
