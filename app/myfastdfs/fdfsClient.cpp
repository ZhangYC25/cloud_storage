#include "fdfsClient.h"

FdfsClient::FdfsClient():conf_path("/etc/fdfs/client.conf"){
    fdfs_client_init(conf_path);
	ConnectionInfo* pTrackerServer = tracker_get_connection();
    std::cerr << "fdfs init sucess" << std::endl;
}

FdfsClient::~FdfsClient(){
    tracker_close_connection_ex(pTrackerServer,true);
	fdfs_client_destroy();
}

ConnectionInfo* FdfsClient::getPtrackerServer(){return pTrackerServer;};

std::string FdfsClient::upload_file_to_fastdfs(const char* local_path){
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

std::string FdfsClient::create_temp_file(const std::vector<char>& data) {
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