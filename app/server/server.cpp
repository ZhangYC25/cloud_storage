
#include <iostream>
#include <stdexcept>
//#include "../utils/threadPool.h"
#include "server.h"
//#include "api.h"
// 静态成员初始化
std::atomic<Server*> Server::s_instance{nullptr};

// 单例获取实例
Server& Server::getInstance() {
    static Server instance; // C++11后静态局部变量线程安全
    s_instance.store(&instance);
    return instance;
}

// 初始化服务器
bool Server::init(uint16_t port, int threads, size_t maxReqSize) {
    try {
        // 创建地址和Endpoint
        Pistache::Address addr(Pistache::Ipv4::any(), Pistache::Port(port));
        m_server = std::make_shared<Pistache::Http::Endpoint>(addr);

        // 配置服务器选项
        auto opts = Pistache::Http::Endpoint::options()
            .threads(threads)
            .maxRequestSize(maxReqSize);
        
        m_server->init(opts);
        std::cout << "Server initialized on port " << port << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Server init failed: " << e.what() << std::endl;
        return false;
    }
}

// 注册路由
void Server::setRoutes() {
    m_router = Api::getInstance() -> getRouter();
    if (!m_server) {
        std::cerr << "Server not initialized! Call init() first." << std::endl;
        return;
    }
    m_server->setHandler(m_router.handler());
}

// 启动服务器（阻塞）
void Server::start() {
    if (!m_server) {
        MY_LOG_ERROR("Server not initialized! Call init() first.");
        return;
    }
    // 注册信号处理（捕获Ctrl+C）
    signal(SIGINT, Server::handleSignal);
    std::cout << "Server started, press Ctrl+C to stop..." << std::endl;
    
    m_server->serve();

    // 按依赖顺序销毁
    uploadThreadPool::destroyInstance();
    
    // 确保任务执行完再关连接池
    MySQLConnPool::destroyInstance();
    FdfsConnPool::destroyInstance();
    RedisConnPool::destroyInstance();

    m_server.reset();
    //_api.reset();
    Api::destroyInstance();
}

// 关闭服务器
void Server::shutdown() {
    if (m_server) {
        std::cout << "\nShutting down server..." << std::endl;
        m_server->shutdown();
    }
}

// 信号处理静态函数
void Server::handleSignal(int sig) {
    if (sig == SIGINT) {
        Api::getInstance() -> shutdown();
        Server::getInstance().shutdown();
        std::cout << "\nInstance shutdown..." << std::endl;
    }
}
