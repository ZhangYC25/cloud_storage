#pragma once

#include <iostream>
#include <string>
#include <cstring>
#include <vector>

extern "C" {
    #include "fastdfs/fdfs_client.h"
    #include "fastcommon/logger.h"
}

class FdfsClient{
public:
    FdfsClient();
    ~FdfsClient();
    bool createConnection();
    void closeConnection();

    
    ConnectionInfo* getPtrackerServer();

    // ================= function ==================
    std::string create_temp_file(const std::vector<char>& data);
    std::string upload_file_to_fastdfs(const char* local_path);

    bool delete_file_from_fastdfs(const std::string& group_name, const std::string& file);

    private:
    const char* conf_path;
    ConnectionInfo* pTrackerServer;

    FdfsClient(const FdfsClient&) = delete;
    FdfsClient& operator=(const FdfsClient&) = delete;
};