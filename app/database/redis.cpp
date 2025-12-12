#include "redis.h"

#include <cstring>
Redis::Redis():redis_ctx(nullptr){
}

Redis::~Redis(){
    this -> close();

}

void Redis::close(){
	if (redis_ctx != nullptr) {
		redisFree(redis_ctx);
		redis_ctx = nullptr;
	}
    
}

bool Redis::connect(){
	this -> close();

	timeval tv = {redis_timeout / 1000, (redis_timeout % 1000) * 1000};
    redis_ctx = redisConnectWithTimeout(redis_host.c_str(), port, tv);
		// 检查Redis连接是否失败
	if (redis_ctx == nullptr || redis_ctx->err) {
		std::cerr << "Redis连接失败: " << (redis_ctx ? redis_ctx->errstr : "内存分配错误") << std::endl;
		// 释放连接（若存在）
		if (redis_ctx) close();			// 返回服务端错误响应
		return false;
		}
	
		/************************ 2. 执行Redis AUTH密码认证 ************************/
		// 1. 定义命令和参数
	const char *argv[] = {"AUTH", redis_pass.c_str()};
	size_t argvlen[] = {4, redis_pass.length()}; // 4是"AUTH"的长度

		// 2. 使用 redisCommandArgv 发送命令
		// 传入参数：上下文，参数数量 (2: "AUTH" 和 密码)，参数数组，参数长度数组
	redisReply* redis_reply = (redisReply*)redisCommandArgv(redis_ctx, 2, argv, argvlen);
	
	if (redis_reply == nullptr) {
		std::cerr << "Redis认证命令发送失败: " << redis_ctx->errstr << std::endl;
		close();
		return false;
	}
	
		// 校验认证结果：成功返回"OK"，失败返回错误信息
	if ((redis_reply->type == REDIS_REPLY_STATUS && strcasecmp(redis_reply->str, "OK") == 0)) {
		//std::cerr << "Redis密码认证失败: " << (redis_reply->str ? redis_reply->str : "未知错误") << std::endl;
		//std::cout << "Redis密码认证成功" << std::endl;
		freeReplyObject(redis_reply);  // 释放认证响应
		//redis_ctx = nullptr;
		return true;
	}
	//std::cout << "Redis密码认证成功" << std::endl;
	freeReplyObject(redis_reply);  // 释放认证响应（必须释放，避免内存泄漏）
	return false;
}

redisContext* Redis::getRedisContext(){
    // 无效则自动重连
	if (!isConnected()) {
		std::cerr << "Redis connection invalid, try reconnect..." << std::endl;
		if (!connect()) {
			return nullptr;
		}
	}
	return this->redis_ctx;
}

bool Redis::isConnected() const{
	if (redis_ctx == nullptr) {
		std::cerr<<"Redis: invalid connection"<<std::endl;
		return false;
	}
	// 发送 PING 命令检测连接是否存活
	redisReply* reply = (redisReply*)redisCommand(redis_ctx, "PING");
	if (reply == nullptr) {
    	std::cerr<<"Redis: invalid connection, non-exist"<<std::endl;
		return false;
	}
	if (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "PONG") == 0) {
		//std::cerr<<"Redis: valid connection"<<std::endl;
		freeReplyObject(reply);
		return true;
	} else {
		std::cerr<<"Redis: invalid reply: "<< reply->str <<std::endl;
		freeReplyObject(reply);
		return false;
	}
}

// ====================== command ======================

bool Redis::set(const std::string& key, const std::string& value, int expire){
	// 先判断核心句柄，空则返回
    if (redis_ctx == nullptr) {
        std::cerr << "[Redis ERROR] redis_ctx is nullptr" << std::endl;
        return false;
    }
	redisReply* reply = nullptr;
    try {
        // 执行SETEX命令（注意：hiredis的redisCommand是格式化命令，存在注入风险，后续可优化为redisCommandArgv）
        reply = (redisReply*)redisCommand(redis_ctx, "SETEX %s %d %s",
                                                          key.c_str(), expire, value.c_str());

        // 处理错误情况
        if (reply == nullptr || reply->type == REDIS_REPLY_ERROR) {
            std::cerr << "[Redis INFO] Failed SET (md5, filename): " << (reply ? reply->str : "nullptr") << std::endl;
			freeReplyObject(reply);
            return false;
        }

        // 校验SETEX执行结果
        if (!(reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0)) {
            std::cerr << "[Redis INFO] Failed SET (md5, filename)! " << (reply->str ? reply->str : "Unkown Response!") << std::endl;
            freeReplyObject(reply);
			return false;
        }
		freeReplyObject(reply);
        return true;
    } catch (const std::bad_alloc& e) {
        // 捕获内存分配异常
        std::cerr << "[Redis ERROR] SET failed: memory allocation failed - " << e.what() << std::endl;
		freeReplyObject(reply);
        return false;
    } catch (const std::exception& e) {
        // 捕获其他标准异常
        std::cerr << "[Redis ERROR] SET failed: " << e.what() << std::endl;
		freeReplyObject(reply);
        return false;
    } catch (...) {
        // 捕获所有未处理的异常（兜底）
        std::cerr << "[Redis ERROR] SET failed: unknown exception" << std::endl;
		freeReplyObject(reply);
        return false;
    }
}


std::string Redis::get(const std::string& key) {
	if (redis_ctx == nullptr) {
        std::cerr << "[Redis ERROR] redis_ctx is nullptr" << std::endl;
        return "";
    }
	redisReply* reply = nullptr;
    try {
        reply = (redisReply*)redisCommand(redis_ctx, "GET %s", key.c_str());

        // 处理错误情况：reply为空 或 不是字符串类型
        if (reply == nullptr || reply->type != REDIS_REPLY_STRING) {
            std::cerr << "[Redis INFO] GET failed: no value or invalid type for key: " << key << std::endl;
			freeReplyObject(reply);
            return "";
        }

        // 正常返回结果
        std::string res = reply->str;
        std::cerr << "[Redis INFO] GET successed: " << res << std::endl;
		freeReplyObject(reply);
        return res;
    } catch (const std::bad_alloc& e) {
        std::cerr << "[Redis ERROR] GET failed: memory allocation failed - " << e.what() << std::endl;
		freeReplyObject(reply);
        return "";
    } catch (const std::exception& e) {
        std::cerr << "[Redis ERROR] GET failed: " << e.what() << std::endl;
		freeReplyObject(reply);
        return "";
    } catch (...) {
        std::cerr << "[Redis ERROR] GET failed: unknown exception" << std::endl;
		freeReplyObject(reply);
        return "";
    }
}

