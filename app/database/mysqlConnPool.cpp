#include <iostream>
#include <memory>

#include "mysqlConnPool.h"

// 静态成员初始化
MySQLConnPool* MySQLConnPool::_poolInstance = nullptr;
std::mutex MySQLConnPool::_instanceMtx;

// 私有构造函数
MySQLConnPool::MySQLConnPool() : _minConn(2), _maxConn(20){}

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
        Mysql::setConfig();
    }
    return _poolInstance;
}

void MySQLConnPool::init() {
    // 避免重复初始化
    if (_currentConn > 0) {
        //std::cerr << "[MySQLConnPool] Warning Connection pool already initialized." << std::endl;
        MY_LOG_WARN("MySQLConnPool Connection pool already initialized");
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
            //std::cerr << "[MySQLConnPool] create initial conn " << _currentConn << " failed!" << std::endl;
            MY_LOG_ERROR("MySQLConnPool create initial conn ", static_cast<int>(_currentConn), "failed!");
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
            if (connPtr && connPtr -> ping()) { // 连接有效
                std::cerr << "[MySQLConnPool] Get conn from pool success!" << " Queue size: "<< _connQueue.size()
                 <<", Current conn nums: "<< static_cast<int>(_currentConn) << std::endl;
                //MY_LOG_INFO("MySQLConnPool Get conn from pool success! Queue size: ", _connQueue.size(),
                 //", Current conn nums: ", static_cast<int>(_currentConn));
                return connPtr;
            } else {
                // 连接无效，丢弃并继续循环尝试获取
                _currentConn--;
                //std::cerr << "[MySQLConnPool] Found invalid conn, discard it. CurrentConn=" 
                            //<< static_cast<int>(_currentConn) << std::endl;
                MY_LOG_ERROR("MySQLConnPool Found invalid conn, discard it. CurrentConn= ", static_cast<int>(_currentConn));
                continue; 
            }   
        }

        // 2. 队列为空，但未达到最大连接数，则创建新连接
        if (_currentConn < _maxConn) {
            connPtr = std::make_shared<Mysql>();
            if (connPtr->getConn() != nullptr) {
                _currentConn++;
                std::cerr<<"[MySQLConnPool] expend MySQL conn success" <<
                 " Queue size: "<< _connQueue.size()<<", Current conn nums: "<< static_cast<int>(_currentConn) <<std::endl;
                //MY_LOG_INFO("MySQLConnPool Expend MySQL conn success! Queue size: ", 
                    //_connQueue.size(), ", Current conn nums: ", static_cast<int>(_currentConn));
                 return connPtr; // 返回 shared_ptr
            } else {
                _currentConn--;
                //std::cerr << "[MySQLConnPool] create invalid conn, currentConn=" 
                            //<< static_cast<int>(_currentConn) << std::endl;
                MY_LOG_ERROR("MySQLConnPool Create invalid conn, currentConn= ", static_cast<int>(_currentConn));
            }
        }

        // 3. 队列为空，且已达到最大连接数，则等待
        std::cout << "[MysqlConnPool]  pool full (max=" << (int)_maxConn 
                      << "), wait for conn..." << std::endl;  
        MY_LOG_WARN("MysqlConnPool Pool fulled (max: ",(int)_maxConn, "), wait for conn...");
        // lambda 谓词，条件满足时返回 true，避免虚假唤醒
        bool success = _cv.wait_for(lock, std::chrono::seconds(3), [this] {
            return !_connQueue.empty();
        });

        if (success) {
            // 等待成功，队列中有连接
            connPtr = _connQueue.front();
            _connQueue.pop();
            std::cerr << "[MySQLConnPool] wait conn success!"<<" Queue size: "<<_connQueue.size()
             <<", Current conn nums: "<<static_cast<int>(_currentConn)<< std::endl;
            //MY_LOG_INFO("MySQLConnPool Wait conn success! Queue size: ",_connQueue.size(),
             //", Current conn nums: ", static_cast<int>(_currentConn));
            return connPtr;
        } else {
            // 等待超时
            //std::cerr << "[MySQLConnPool] wait conn timeout!" << std::endl;
            MY_LOG_ERROR("MySQLConnPool Wait conn timeout!");
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
    //MY_LOG_INFO("MySQLConnPool Success release connection! Queue size: ", _connQueue.size(),
        //", Current conn nums: ", static_cast<int>(_currentConn));
    
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
    //std::cout << "Info: MySQL Connection pool destroyed." << std::endl;
}

void MySQLConnPool::destroyInstance() {
    std::lock_guard<std::mutex> lock(_instanceMtx); // 注意这里用的是保护单例的静态锁
    if (_poolInstance) {
        _poolInstance->destroyPool(); // 先清理内部连接
        delete _poolInstance;         // 再释放池对象本身
        _poolInstance = nullptr;      // 置空，防止野指针
    }
    //std::cout<<"Info: MySQL Instance destroyed."<<std::endl;
}
