#include "fdfsClient.h"

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
		tracker_close_connection_ex(pTrackerServer,true);
		fdfs_client_destroy();
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

// std::string FdfsClient::create_temp_file(const std::vector<char>& data) {
//     char temp_template[] = "/tmp/fastdfs_upload_XXXXXX";
//     int fd = mkstemp(temp_template);
//     if (fd == -1) {
//         //std::cerr <<"[Fdfs ERROR] Failed create tmp file!"<<std::endl;
//         MY_LOG_ERROR("Fdfs Create tmp file failed");
//         return "";
//     }
    
//     ssize_t written = write(fd, data.data(), data.size());
    
//     if (written != static_cast<ssize_t>(data.size())) {
//         close(fd);
//         //std::cerr <<"[Fdfs ERROR] Failed written tmp file!"<<std::endl;
//         MY_LOG_ERROR("Fdfs written tmp file failed");
//         unlink(temp_template); // 删除创建的临时文件
//         return "";
//     }
//     close(fd);
//     std::cerr <<"[Fdfs INFO] Successed create tmp file!"<<std::endl;
//     return std::string(temp_template);
// }

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

bool FdfsClient::delete_file_from_fastdfs(const std::string& group_name, const std::string& file){
    ConnectionInfo storageServer;
	memset(&storageServer, 0, sizeof(storageServer));

    int result = tracker_query_storage_update(
        pTrackerServer,
        &storageServer,
        group_name.c_str(),
        file.c_str()
    );
    if (result != 0) {
        // std::cerr << "Failed to query storage server for file: " 
        //           << group_name << "/" << file 
        //           << ", error code: " << result << std::endl;
        MY_LOG_ERROR("Fdfs Query file: ",group_name, 
                    "/", file, "failed , error code: ", result);
        return false;
    }
    if(storage_delete_file(pTrackerServer,&storageServer,
        group_name.c_str(), file.c_str())) {
            //std::cerr << "delete fdfs error" << std::endl;
            MY_LOG_ERROR("Fdfs Delete file", group_name, "/",file, " failed");
            return false;
        }
    return true;
    
}
