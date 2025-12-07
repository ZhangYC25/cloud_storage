#pragma once

#include <redis/hiredis.h>

#include <string>
#include <memory>
#include <iostream>
#include <stdexcept>
#include <cstdarg> // For va_list

class Redis {
public:
    // 构造函数负责创建和认证连接
    Redis();
    ~Redis();

    redisContext* getRedisContext();
    Redis(const Redis&) = delete;
    Redis& operator=(const Redis&) = delete;

    // 检查连接是否有效 (如果认证失败或连接中断，返回 false)
    bool isConnected() const { return redis_ctx != nullptr; }
    void connect();
private:
    redisContext* redis_ctx; 
    const std::string redis_host = "127.0.0.1";
    const std::string redis_pass = "ZYCzyc520@APEX!";
    const int redis_timeout = 5000;
    unsigned int port = 6379;
};