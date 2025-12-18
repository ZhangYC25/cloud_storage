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
            //std::cout << "FastDFS全局初始化成功" << std::endl;
        }

        // 第二步：创建连接池的初始连接（多个独立连接）
        if (_currentConn > 0) {
            //std::cerr << "[FdfsLConnPool] Warning Connection pool already initialized." << std::endl;
            MY_LOG_WARN("FdfsLConnPool Connection pool already initialized");
            return;
        }

        for (int i = 0; i < _minConn; ++i) {
            auto connPtr = std::make_shared<FdfsClient>();
            if (connPtr->getPtrackerServer() != nullptr) {
                _connQueue.push(connPtr);
                _currentConn++;
            } else {
                //std::cerr << "[FdfsConnPool] create initial conn " << static_cast<int>(_currentConn) << " failed!" << std::endl;
                MY_LOG_ERROR("FdfsConnPool create initial conn ", static_cast<int>(_currentConn), "failed!");
            }
        }
        std::cout << "[FdfsConnPool] init success: (conn=" << static_cast<int>(_currentConn) <<")"<< std::endl;
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
    std::unique_lock<std::mutex> lock(_mtx);
    while (true) {
        std::shared_ptr<FdfsClient> connPtr = nullptr;
        if (!_connQueue.empty()) {
            connPtr = _connQueue.front();
            _connQueue.pop();
            std::cerr << "[FdfsConnPool] Success get connection! Queue Size = " 
                            << _connQueue.size() <<", Current conn nums: "<<static_cast<int>(_currentConn)<< std::endl;
            //MY_LOG_INFO("FdfsConnPool Success get connection! Queue Size: ", _connQueue.size(), 
            //              ", Current conn nums: ", static_cast<int>(_currentConn));
            return connPtr;
        }

        // 2. 队列为空，但未达到最大连接数，则创建新连接
        if (_currentConn < _maxConn) {
            connPtr = std::make_shared<FdfsClient>();
            if (connPtr->getPtrackerServer() != nullptr) {
                _currentConn++;
                std::cerr<<"[FdfsConnPool] expend fastdfs conn success!" <<
                 " Queue size: "<< _connQueue.size()<<", Current conn nums: "<< static_cast<int>(_currentConn) <<std::endl;
                //MY_LOG_INFO("FdfsConnPool Expend MySQL conn success! Queue size: ", 
                    //_connQueue.size(), ", Current conn nums: ", static_cast<int>(_currentConn));
                return connPtr; // 返回 shared_ptr
            } else {
                _currentConn--;
                // std::cerr << "[FdfsConnPool] create invalid conn, currentConn=" 
                //             << static_cast<int>(_currentConn) << std::endl;
                MY_LOG_ERROR("FdfsConnPool Create invalid conn, currentConn= ", static_cast<int>(_currentConn));
            
            }
        }

        // 3. 队列为空，且已达到最大连接数，则等待
        std::cout << "[FdfsConnPool]  pool full (max=" << (int)_maxConn 
                      << "), wait for conn..." << std::endl;
        MY_LOG_WARN("FdfsConnPool Pool fulled (max: ",(int)_maxConn, "), wait for conn...");
        // lambda 谓词，条件满足时返回 true，避免虚假唤醒
        bool success = _cv.wait_for(lock, std::chrono::seconds(5), [this] {
            return !_connQueue.empty();
        });

        if (success) {
            // 等待成功，队列中有连接
            connPtr = _connQueue.front();
            _connQueue.pop();
            std::cerr << "[FdfsConnPool] wait conn success!"<<" Queue size: "<<_connQueue.size()
             <<", Current conn nums: "<<static_cast<int>(_currentConn)<< std::endl;

            //MY_LOG_INFO("FdfsConnPool Wait conn success! Queue size: ",_connQueue.size(),
             //", Current conn nums: ", static_cast<int>(_currentConn));
            return connPtr;
        } else {
            // 等待超时
            //std::cerr << "[FdfsConnPool] wait conn timeout!" << std::endl;
            MY_LOG_ERROR("FdfsConnPool Wait conn timeout!");
            return nullptr;
        }
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
    std::cout << "[FdfsConnPool] Success release connection! Queue size: " 
                << _connQueue.size() << ", Current conn nums: " << static_cast<int>(_currentConn) << std::endl;
    //MY_LOG_INFO("FdfsConnPool Success release connection! Queue size: ", _connQueue.size(),
        //", Current conn nums: ", static_cast<int>(_currentConn));
    return true;
}
