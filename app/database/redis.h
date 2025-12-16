#pragma once

#include <redis/hiredis.h>

#include <string>
#include <memory>
#include <iostream>
#include <stdexcept>
#include <vector>
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
    bool isConnected() const;
    bool connect();
    void close();
    
    // ============ redis command ===================
    bool set(const std::string& key, const std::string& value, int expire);
    std::string get(const std::string& key);
    bool del(const std::string& key);
    
    bool expire(const std::string& key, int seconds);

private:
    redisContext* redis_ctx; 
    const std::string redis_host = "127.0.0.1";
    const std::string redis_pass= "ZYCzyc520@APEX!";
    int redis_timeout = 5000;
    const int port = 6379;

};
