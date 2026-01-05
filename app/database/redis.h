#pragma once

#include <redis/hiredis.h>

#include <string>
#include <memory>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cstdarg> // For va_list

#include "../utils/asyncLogger.h"
class Redis {
public:
    // 构造函数负责创建和认证连接
    Redis();
    ~Redis();
    static void setConfig();

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

    bool hset(const std::string& key, const std::string& field, const std::string& value);

    std::string hget(const std::string& key, const std::string& field);

    bool exists(const std::string& key);

    int sadd(const std::string& key, const std::string& member);

    int scard(const std::string& key);

private:
    redisContext* redis_ctx; 
    
    int redis_timeout = 5000;
    static std::string redis_host;
    static std::string redis_pass;
    static int port;
};
