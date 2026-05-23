#pragma once

#include <string>

class FdfsConnPool;

namespace fdfs_ops {

void deleteFile(FdfsConnPool* pool, const std::string& url);

}  // namespace fdfs_ops
