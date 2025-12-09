#include "mysqlConnPool.h"
#include "Mysql.h"

#include <iostream>
#include <memory>

// 静态成员初始化
MySQLConnPool* MySQLConnPool::_poolInstance = nullptr;

// 私有构造函数
MySQLConnPool::MySQLConnPool() : _currentConn(0), _minConn(3), _maxConn(10){}

// 私有析构函数
MySQLConnPool::~MySQLConnPool() {
    //destroyPool();
}

/**
 * @brief 获取连接池单例
 * @return ConnectionPool* 实例指针
 */
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

/**
 * @brief 内部函数：创建一个新的数据库连接
 * @return MYSQL* 成功返回连接指针，失败返回 nullptr
 */
/*Mysql* MySQLConnPool::createConnection() {
    return new(Mysql);
}*/

/**
 * @brief 初始化连接池
 * @param ... 数据库连接参数和连接池大小参数
 */
void MySQLConnPool::init() {
    // 避免重复初始化
    if (_currentConn > 0) {
        std::cerr << "Warning: Connection pool already initialized." << std::endl;
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
            std::cerr << "Error: Failed to create initial connection " << i + 1 << std::endl;
        }
    }

    std::cout << "Info: Connection pool initialized with " << _currentConn << " connections." << std::endl;
}

/**
 * @brief 从连接池中获取一个连接
 * @return MYSQL* 连接指针，超时或失败返回 nullptr
 */
std::shared_ptr<Mysql> MySQLConnPool::getConnection() {
    std::shared_ptr<Mysql> connPtr = nullptr;
    std::unique_lock<std::mutex> lock(_mtx);

    // 1. 队列中有可用连接
    if (!_connQueue.empty()) {
        connPtr = _connQueue.front();
        _connQueue.pop();
        return connPtr;
    }

    // 2. 队列为空，但未达到最大连接数，则创建新连接
    if (_currentConn < _maxConn) {
        connPtr = std::make_shared<Mysql>();
        if (connPtr->getConn() != nullptr) {
            _currentConn++;
            return connPtr; // 返回 shared_ptr
        }
        // 如果创建失败，继续执行等待逻辑
    }

    // 3. 队列为空，且已达到最大连接数，则等待
    // 等待一个连接释放到队列中（设置一个超时时间，例如 5 秒）
    std::cout << "Warning: Pool is full, waiting for connection release..." << std::endl;
    
    // lambda 谓词，条件满足时返回 true，避免虚假唤醒
    bool success = _cv.wait_for(lock, std::chrono::seconds(5), [this] {
        return !_connQueue.empty();
    });

    if (success) {
        // 等待成功，队列中有连接
        connPtr = _connQueue.front();
        _connQueue.pop();
        return connPtr;
    } else {
        // 等待超时
        std::cerr << "Error: Wait for connection timeout." << std::endl;
        return nullptr;
    }
}

/**
 * @brief 将连接放回连接池
 * @param conn 要释放的连接
 * @return bool 是否成功释放
 */
bool MySQLConnPool::releaseConnection(std::shared_ptr<Mysql> connPtr) {
    if (connPtr == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(_mtx);

    _connQueue.push(connPtr);

    // 唤醒一个正在等待连接的线程
    _cv.notify_one();
    return true;
}

/**
 * @brief 销毁连接池（释放所有连接）
 */
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