#include "redisConnPool.h"

RedisConnPool* RedisConnPool::_redisInstance = nullptr;

RedisConnPool::RedisConnPool():_minConn(3),_maxConn(10){}
RedisConnPool::~RedisConnPool(){
    destroyPool();
}
// 销毁连接池：清空所有连接

RedisConnPool* RedisConnPool::getInstance(){
    if (_redisInstance == nullptr) {
        static std::mutex instanceMutex;
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (_redisInstance == nullptr) {
            _redisInstance = new RedisConnPool();
        }
    }
    return _redisInstance;
}

void RedisConnPool::destroyPool() {
    std::lock_guard<std::mutex> lock(_mtx);
    while (!_connQueue.empty()) {
        _connQueue.pop();
    }
    _currentConn = 0;
    std::cout << "[RedisConnPool] destroyed" << std::endl;
}

void RedisConnPool::init(){
    std::lock_guard<std::mutex> lock(_mtx);
    if (_currentConn > 0) {
        std::cerr << "[RedisConnPool] Warning Connection pool already initialized." << std::endl;
        return;
    }
    //_maxConn = 10
    for (int i = 0;i < _minConn; i++) {
        std::shared_ptr<Redis> redisConn = std::make_shared<Redis>();
        if (redisConn -> connect() && redisConn->isConnected()) {
            _connQueue.push(redisConn);
            _currentConn++;
        } else {
            std::cerr << "[RedisConnPool] create initial conn " << static_cast<int>(_currentConn) << " failed!" << std::endl;
        }
    }
    std::cout << "[RedisConnPool] init success (conn=" << static_cast<int>(_currentConn) << ")" << std::endl;
}

std::shared_ptr<Redis> RedisConnPool::getConnection(){
    std::unique_lock<std::mutex> lock(_mtx);
    while (true) {
        // 1. 先尝试从队列拿一个
        if (!_connQueue.empty()) {
            std::shared_ptr<Redis> conn = _connQueue.front();
            _connQueue.pop();

            if (conn && conn->isConnected()) {
                std::cerr << "[RedisConnPool] Success get connection! Queue Size = " 
                          << _connQueue.size() << ", Current conn nums: "<<static_cast<int>(_currentConn)<<std::endl;
                return conn;
            } else {
                // 无效连接：丢弃，不放回
                _currentConn--;
                std::cerr << "[RedisConnPool] discard invalid conn, currentConn=" 
                          << static_cast<int>(_currentConn) << std::endl;
                // conn 智能指针在这里析构，连接会被 close
            }
        } 
        // 2. 队列为空，但还能创建新连接
        else if (_currentConn < _maxConn) {
            lock.unlock();  // 创建连接时解锁，避免阻塞
            auto newConn = std::make_shared<Redis>();
            if (newConn->connect()) {
                lock.lock();
                if (newConn -> isConnected()) {
                    _currentConn++;
                    std::cerr<<"[RedisConnPool] expend Redsi conn success!" <<
                 " Queue size: "<< _connQueue.size()<<", Current conn nums: "<< static_cast<int>(_currentConn) <<std::endl;
                    return newConn;
                } else {
                    std::cerr << "[RedisConnPool] create invalid conn, currentConn=" 
                          << static_cast<int>(_currentConn) << std::endl;
                }
            } else {
                lock.lock();
                std::cerr << "[RedisConnPool] create new conn failed!" << std::endl;
                // 创建失败，不计入 currentConn
            }
        }
        // 3. 队列空，已达最大连接：等待
        else {
            std::cout << "[RedisConnPool]  pool full (max=" << (int)_maxConn 
                      << "), wait for conn..." << std::endl;
            
            bool success = _cv.wait_for(lock, std::chrono::seconds(_timeoutSec), [this](){
                return !_connQueue.empty();
            });

            if (!success) {
                std::cerr << "[RedisConnPool] wait conn timeout!" << std::endl;
                return nullptr;
            }
            std::cerr << "[RedisConnPool] wait conn success!"<<" Queue size: "<<_connQueue.size()
             <<", Current conn nums: "<<static_cast<int>(_currentConn)<< std::endl;
            // 醒来后继续循环尝试获取
        }
    }
}

void RedisConnPool::releaseConnection(std::shared_ptr<Redis> clientPtr) {
    if (!clientPtr) {
        std::cerr << "[RedisConnPool] try to release null conn!" << std::endl;
        return;
    }

    try {
        std::lock_guard<std::mutex> lock(_mtx);
        // 只放回有效连接
        if (clientPtr -> isConnected()) {
            _connQueue.push(clientPtr);
            _cv.notify_one(); // 唤醒等待的线程
            std::cout << "[RedisConnPool] Success release connection! Queue size: " 
                << _connQueue.size() << ", Current conn nums: " << static_cast<int>(_currentConn) << std::endl;
        } else {
            _currentConn--;
            std::cerr << "[RedisConnPool] release invalid conn, currentConn=" << static_cast<int>(_currentConn) << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "[RedisConnPool] release conn failed: " << e.what() << std::endl;
    }
}
