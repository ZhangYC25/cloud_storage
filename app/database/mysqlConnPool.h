#pragma once

#include "Mysql.h"
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <memory>

#include <mysql/mysql.h>

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

    int _currentConn;
    int _maxConn;
    int _minConn;

    //怎么取？ _connQueue.pop() -> conn;
    std::queue<std::shared_ptr<Mysql>> _connQueue;
    
    std::mutex _mtx;
    std::condition_variable _cv;

    // 内部函数：创建一个新的数据库连接
    //Mysql* createConnection();

    // 静态指针，指向唯一的连接池实例
    static MySQLConnPool* _poolInstance;
};