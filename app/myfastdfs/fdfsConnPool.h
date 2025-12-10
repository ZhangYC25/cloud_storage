#pragma once

#include "fdfsClient.h"

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

class FdfsConnPool{
public:
    static FdfsConnPool* getInstance();

    FdfsConnPool(const FdfsConnPool&) = delete;
    FdfsConnPool& operator=(const FdfsConnPool&) = delete;
    FdfsConnPool(FdfsConnPool&&) = delete;
    FdfsConnPool& operator=(FdfsConnPool&&) = delete;
    
    void destroyPool();

    void init();

    // 从连接池中获取一个连接
    std::shared_ptr<FdfsClient> getConnection();

    // 将连接放回连接池
    bool releaseConnection(std::shared_ptr<FdfsClient>);
private:
    FdfsConnPool();
    ~FdfsConnPool();

    int _currentConn;
    int _maxConn;
    int _minConn;

    //怎么取？ _connQueue.pop() -> conn;
    std::queue<std::shared_ptr<FdfsClient>> _connQueue;
    
    std::mutex _mtx;
    std::condition_variable _cv;
    // 静态指针，指向唯一的连接池实例
    static FdfsConnPool* _poolInstance;
    static bool _global_init_done;
};