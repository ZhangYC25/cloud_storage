#include "mysqlConnPool.h"
#include "Mysql.h"

#include <iostream>
#include <memory>

// 静态成员初始化
MySQLConnPool* MySQLConnPool::_poolInstance = nullptr;

// 私有构造函数
MySQLConnPool::MySQLConnPool() : _minConn(2), _maxConn(10){}

// 私有析构函数
MySQLConnPool::~MySQLConnPool() {
    //destroyPool();
}

MySQLConnPool* MySQLConnPool::getInstance() {
    // 线程安全的单例初始化（C++11 magic static 保证线程安全）
    // 或者使用双重检查锁定 (DCLP)
    if (_poolInstance == nullptr) {
        static std::mutex instanceMutex;
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (_poolInstance == nullptr) {
            _poolInstance = new MySQLConnPool();
        }
    }
    return _poolInstance;
}

void MySQLConnPool::init() {
    // 避免重复初始化
    if (_currentConn > 0) {
        std::cerr << "[MySQLConnPool] Warning Connection pool already initialized." << std::endl;
        return;
    }
    // 预先创建最小连接数
    for (int i = 0; i < _minConn; ++i) {
        //Mysql* conn = createConnection();
        std::shared_ptr<Mysql> connPtr = std::make_shared<Mysql>();
        if (connPtr) {
            std::lock_guard<std::mutex> lock(_mtx);
            _connQueue.push(connPtr);
            _currentConn++;
        } else {
            // 如果连接失败，可以根据需要决定是否退出
            std::cerr << "[MySQLConnPool] create initial conn " << _currentConn << " failed!" << std::endl;
        }
    }

    std::cout << "[MySQLConnPool] init success: (conn=" << (int)_currentConn << ")" << std::endl;
}

std::shared_ptr<Mysql> MySQLConnPool::getConnection() {
    std::unique_lock<std::mutex> lock(_mtx);

    while (true) {
        std::shared_ptr<Mysql> connPtr = nullptr;
        // 1. 队列中有可用连接
        if (!_connQueue.empty()) {
            connPtr = _connQueue.front();
            _connQueue.pop();
            std::cerr << "[MySQLConnPool] Success get connection! Queue Size = " 
                            << _connQueue.size() << ", Current conn nums: "<<static_cast<int>(_currentConn)<<std::endl;
            return connPtr;
        }

        // 2. 队列为空，但未达到最大连接数，则创建新连接
        if (_currentConn < _maxConn) {
            connPtr = std::make_shared<Mysql>();
            if (connPtr->getConn() != nullptr) {
                _currentConn++;
                std::cerr<<"[MySQLConnPool] expend MySQL conn success!" <<
                 " Queue size: "<< _connQueue.size()<<", Current conn nums: "<< static_cast<int>(_currentConn) <<std::endl;
                return connPtr; // 返回 shared_ptr
            } else {
                _currentConn--;
                std::cerr << "[MySQLConnPool] create invalid conn, currentConn=" 
                            << static_cast<int>(_currentConn) << std::endl;
            }
        }

        // 3. 队列为空，且已达到最大连接数，则等待
        std::cout << "[FdfsConnPool]  pool full (max=" << (int)_maxConn 
                      << "), wait for conn..." << std::endl;  
        
        // lambda 谓词，条件满足时返回 true，避免虚假唤醒
        bool success = _cv.wait_for(lock, std::chrono::seconds(5), [this] {
            return !_connQueue.empty();
        });

        if (success) {
            // 等待成功，队列中有连接
            connPtr = _connQueue.front();
            _connQueue.pop();
            std::cerr << "[MySQLConnPool] wait conn success!"<<" Queue size: "<<_connQueue.size()
             <<", Current conn nums: "<<static_cast<int>(_currentConn)<< std::endl;
            return connPtr;
        } else {
            // 等待超时
            std::cerr << "[MySQLConnPool] wait conn timeout!" << std::endl;
            return nullptr;
        }
    }
}

bool MySQLConnPool::releaseConnection(std::shared_ptr<Mysql> connPtr) {
    if (connPtr == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(_mtx);

    _connQueue.push(connPtr);
    std::cout << "[MySQLConnPool] Success release connection! Queue size: " 
                << _connQueue.size() << ", Current conn nums: " << static_cast<int>(_currentConn) << std::endl;
    // 唤醒一个正在等待连接的线程
    _cv.notify_one();
    return true;
}

void MySQLConnPool::destroyPool() {
    std::lock_guard<std::mutex> lock(_mtx);

    // 关闭并清理队列中的所有连接
    while (!_connQueue.empty()) {
        _connQueue.pop();
    }
    
    _currentConn = 0;
    std::cout << "Info: Connection pool destroyed." << std::endl;
    
    //delete _poolInstance;
    // 注意：如果是堆上创建的单例，需要 delete _poolInstance
    // 但在 C++ 中，单例的销毁时机通常由程序结束时自动管理
    // 这里我们只清理连接资源
}
