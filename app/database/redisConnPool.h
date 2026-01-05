#pragma once

//#include "redis.h"
#include <queue>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <stdexcept>

#include "redis.h"

class RedisConnPool {
public:
    // 获取连接池单例
    static RedisConnPool* getInstance();
    static void destroyInstance();
    // 显式初始化连接池（必须在 main 函数中调用）
    void init();

    // 从连接池获取连接
    std::shared_ptr<Redis> getConnection();

    // 将连接放回连接池
    void releaseConnection(std::shared_ptr<Redis> clientPtr);
    
    // 销毁连接池
    void destroyPool();

    bool isRelax(){return _connQueue.size() == _currentConn;}
private:
    RedisConnPool();
    ~RedisConnPool();
    
    RedisConnPool(const RedisConnPool&) = delete;
    RedisConnPool& operator=(const RedisConnPool&) = delete;

    static RedisConnPool* _redisInstance;

    // 连接池状态和配置
    int8_t _minConn = 0;
    int8_t _maxConn = 0;
    std::atomic<int8_t> _currentConn = 0; // 当前连接总数
    int8_t _timeoutSec = 5;  // 获取连接的超时时间

    const std::string _redis_host = "127.0.0.1";
    int _port = 6379;
    const std::string redis_pass = "ZYCzyc520@APEX!";
    int redis_timeout = 5000;
    
    // 队列和同步原语
    std::queue<std::shared_ptr<Redis>> _connQueue;
    std::mutex _mtx;
    static std::mutex _instanceMtx;
    std::condition_variable _cv;
};

