#pragma once
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <atomic>
#include <mysql/mysql.h>

#include "Mysql.h"

class MySQLConnPool {

public:
    // 获取连接池单例
    static MySQLConnPool* getInstance();

    MySQLConnPool(const MySQLConnPool&) = delete;
    MySQLConnPool& operator=(const MySQLConnPool&) = delete;
    MySQLConnPool(MySQLConnPool&&) = delete;
    MySQLConnPool& operator=(MySQLConnPool&&) = delete;

    void destroyPool();

    void init();
   
    // 从连接池中获取一个连接
    std::shared_ptr<Mysql> getConnection();

    // 将连接放回连接池
    bool releaseConnection(std::shared_ptr<Mysql>);
private:
    //建立连接、释放连接
    MySQLConnPool();
    ~MySQLConnPool();

    std::atomic<int8_t> _currentConn{0};
    int8_t _maxConn;
    int8_t _minConn;

    //怎么取？auto conn = _connQueue->front();
    std::queue<std::shared_ptr<Mysql>> _connQueue;
    
    std::mutex _mtx;
    std::condition_variable _cv;

    // 静态指针，指向唯一的连接池实例
    static MySQLConnPool* _poolInstance;
};

