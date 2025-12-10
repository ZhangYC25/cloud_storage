#include "fdfsConnPool.h"


FdfsConnPool* FdfsConnPool::_poolInstance = nullptr;
bool FdfsConnPool::_global_init_done = false;
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
    // 第一步：全局只初始化1次fdfs_client
        std::lock_guard<std::mutex> initLock(_mtx);
        if (!_global_init_done) {
            if (fdfs_client_init("/etc/fdfs/client.conf") != 0) {
                std::cerr << "FastDFS全局初始化失败!检查client.conf" << std::endl;
                exit(1); // 初始化失败直接退出，避免后续无效操作
            }
            _global_init_done = true;
            std::cout << "FastDFS全局初始化成功" << std::endl;
        }

        // 第二步：创建连接池的初始连接（多个独立连接）
        if (_currentConn > 0) {
            std::cerr << "连接池已初始化" << std::endl;
            return;
        }

        for (int i = 0; i < _minConn; ++i) {
            auto connPtr = std::make_shared<FdfsClient>();
            if (connPtr->getPtrackerServer() != nullptr) {
                _connQueue.push(connPtr);
                _currentConn++;
            } else {
                std::cerr << "创建初始连接" << i+1 << "失败" << std::endl;
            }
        }
        std::cout << "FdfsPool初始化完成, 当前连接数：" << _currentConn << std::endl;
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
        std::cout<<"get Fdfs connection"<<std::endl;
        return connPtr;
    }

    // 2. 队列为空，但未达到最大连接数，则创建新连接
    if (_currentConn < _maxConn) {
        connPtr = std::make_shared<FdfsClient>();
        if (connPtr->getPtrackerServer() != nullptr) {
            _currentConn++;
            return connPtr; // 返回 shared_ptr
        }
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
    std::cout<<"release fdfsPool"<<std::endl;
    return true;
}