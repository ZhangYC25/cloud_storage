#include "fdfs_ops.h"

#include <iostream>

#include "../../myfastdfs/fdfsConnPool.h"
#include "../../myfastdfs/fdfsClient.h"
#include "../../utils/asyncLogger.h"

namespace fdfs_ops {

namespace {

std::string normalizeFileId(std::string url) {
    if (url.empty()) {
        return url;
    }

    const std::string https_prefix = "https://";
    const std::string http_prefix = "http://";
    if (url.rfind(https_prefix, 0) == 0) {
        url = url.substr(https_prefix.size());
    } else if (url.rfind(http_prefix, 0) == 0) {
        url = url.substr(http_prefix.size());
    }

    const auto first_slash = url.find('/');
    if (first_slash != std::string::npos && first_slash + 1 < url.size()) {
        const std::string maybe_group = url.substr(0, first_slash);
        if (maybe_group.rfind("group", 0) != 0) {
            url = url.substr(first_slash + 1);
        }
    }

    while (!url.empty() && url.front() == '/') {
        url.erase(url.begin());
    }

    return url;
}

}  // namespace

void deleteFile(FdfsConnPool* pool, const std::string& url) {
    const std::string file_id = normalizeFileId(url);
    if (file_id.find('/') == std::string::npos) {
        std::cerr << "[ERROR] Invalid FastDFS file_id (no '/'): \"" << url << "\"" << std::endl;
        return;
    }

    std::shared_ptr<FdfsClient> connFdfs = pool->getConnection();
    if (!connFdfs) {
        MY_LOG_ERROR("Fdfs delete failed: no connection from pool");
        return;
    }

    if (connFdfs->delete_file_from_fastdfs(file_id)) {
        MY_LOG_INFO("Fdfs Delete file success: ", file_id);
    } else {
        MY_LOG_ERROR("Fdfs Delete file failed: ", file_id);
        pool->releaseConnection(connFdfs);
        return;
    }

    pool->releaseConnection(connFdfs);
}

}  // namespace fdfs_ops
