#pragma once

#include "api.h"
#include <csignal>
#include <memory>
#include <string>
#include <mutex>


// 封装Pistache服务器的类
class Server {
public:
    // 单例模式（可选，也可直接实例化）
    static Server& getInstance();
    // 禁用拷贝和移动（避免多实例）
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = delete;
    Server& operator=(Server&&) = delete;

    void setApi(std::shared_ptr<Api> api) {
        std::lock_guard<std::mutex> lock(_mutex); // 线程安全
        if (!_api && api) { // 仅未初始化时注入
            _api = api;
            _api -> setupRoutes();
            std::cout << "Routes registered successfully." << std::endl;
        }
    }

    // 初始化服务器（配置端口、线程数、最大请求大小等）
    bool init(uint16_t port = 2048, int threads = 4, size_t maxReqSize = 1024 * 64);
    
    // 注册路由（外部调用，传入路由配置逻辑）
    void setRoutes();
    
    // 启动服务器（阻塞运行）
    void start();
    
    // 优雅关闭服务器
    void shutdown();

    // 信号处理静态函数（供signal注册）
    static void handleSignal(int sig);

private:
    // 私有构造/析构（单例模式）
    Server():_api(nullptr){}
    ~Server() = default;

    // 成员变量（替代全局变量g_server）
    std::shared_ptr<Api> _api;
    std::shared_ptr<Pistache::Http::Endpoint> m_server;
    Pistache::Rest::Router m_router;
    static std::atomic<Server*> s_instance; // 原子指针保证线程安全
    std::mutex _mutex;
};