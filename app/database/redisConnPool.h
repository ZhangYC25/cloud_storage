#ifndef REDIS_CONN_POOL_H
#define REDIS_CONN_POOL_H

#include "redis.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <stdexcept>

class RedisConnPool {
public:
    // 获取连接池单例
    static RedisConnPool* getInstance();

    // 显式初始化连接池（必须在 main 函数中调用）
    void init();

    // 从连接池获取连接
    std::shared_ptr<Redis> getConnection();

    // 将连接放回连接池
    void releaseConnection(std::shared_ptr<Redis> clientPtr);
    
    // 销毁连接池
    void destroyPool();

private:
    RedisConnPool();
    ~RedisConnPool();
    
    RedisConnPool(const RedisConnPool&) = delete;
    RedisConnPool& operator=(const RedisConnPool&) = delete;

    // DCLP 需要的成员
    static RedisConnPool* _instance;
    static std::mutex _instanceMutex;

    // 连接池状态和配置
    int _minConn = 0;
    int _maxConn = 0;
    int _currentConn = 0; // 当前连接总数
    int _timeoutSec = 5;  // 获取连接的超时时间

    const std::string _redis_host = "127.0.0.1";
    int _port = 6379;
    const std::string redis_pass = "ZYCzyc520@APEX!";
    int redis_timeout = 5000;
    
    // 队列和同步原语
    std::queue<std::shared_ptr<Redis>> _connQueue;
    std::mutex _mtx;
    std::condition_variable _cv;
};

#endif // REDIS_CONN_POOL_H