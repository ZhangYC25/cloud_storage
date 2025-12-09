#include "fdfsConnPool.h"


FdfsConnPool* FdfsConnPool::_poolInstance = nullptr;

// 私有构造函数
FdfsConnPool::FdfsConnPool() : _currentConn(0), _minConn(3), _maxConn(10){}

// 私有析构函数
FdfsConnPool::~FdfsConnPool() {
    //destroyPool();
}
FdfsConnPool* FdfsConnPool::getInstance(){
        if (_poolInstance == nullptr) {
            static std::mutex instanceMutex;
            std::lock_guard<std::mutex> lock(instanceMutex);
            if (_poolInstance == nullptr) {
                _poolInstance = new FdfsConnPool();
            }
        }
        return _poolInstance;
    }

void FdfsConnPool::init(){
    // 避免重复初始化
    if (_currentConn > 0) {
        std::cerr << "Warning: Connection pool already initialized." << std::endl;
        return;
    }
    // 预先创建最小连接数
    for (int i = 0; i < _minConn; ++i) {
        std::shared_ptr<FdfsClient> connPtr = std::make_shared<FdfsClient>();
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

void FdfsConnPool::destroyPool() {
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

// 从连接池中获取一个连接
std::shared_ptr<FdfsClient> FdfsConnPool::getConnection(){

    std::shared_ptr<FdfsClient> connPtr = nullptr;
    std::unique_lock<std::mutex> lock(_mtx);

    // 1. 队列中有可用连接
    if (!_connQueue.empty()) {
        connPtr = _connQueue.front();
        _connQueue.pop();
        return connPtr;
    }

    // 2. 队列为空，但未达到最大连接数，则创建新连接
    if (_currentConn < _maxConn) {
        connPtr = std::make_shared<FdfsClient>();
        if (connPtr->getPtrackerServer() != nullptr) {
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

    // 将连接放回连接池
bool FdfsConnPool::releaseConnection(std::shared_ptr<FdfsClient> connPtr){
    if (connPtr == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(_mtx);

    _connQueue.push(connPtr);

    // 唤醒一个正在等待连接的线程
    _cv.notify_one();
    return true;
}