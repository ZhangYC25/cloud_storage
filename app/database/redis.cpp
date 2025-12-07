#include "redis.h"

#include <cstring>
Redis::Redis(){
}

Redis::~Redis(){
    if (this->redis_ctx != nullptr){
        redisFree(this -> redis_ctx);
    }
}

void Redis::connect(){
    redis_ctx = redisConnect(redis_host.c_str(), port);

		// 检查Redis连接是否失败
	if (redis_ctx == nullptr || redis_ctx->err) {
		std::cerr << "Redis连接失败: " << (redis_ctx ? redis_ctx->errstr : "内存分配错误") << std::endl;
		// 释放连接（若存在）
		if (redis_ctx) redisFree(redis_ctx);			// 返回服务端错误响应
			return;
		}
	
		/************************ 2. 执行Redis AUTH密码认证 ************************/
		// 1. 定义命令和参数
	const char *argv[] = {"AUTH", redis_pass.c_str()};
	size_t argvlen[] = {4, redis_pass.length()}; // 4是"AUTH"的长度

		// 2. 使用 redisCommandArgv 发送命令
		// 传入参数：上下文，参数数量 (2: "AUTH" 和 密码)，参数数组，参数长度数组
	redisReply* redis_reply = (redisReply*)redisCommandArgv(redis_ctx, 2, argv, argvlen);
	//redis_reply = (redisReply*)redisCommand(redis_ctx, "AUTH %s", redis_pass);
	std::cerr << redis_reply -> str << std::endl;
	std::cerr << redis_reply->type << std::endl;
	if (redis_reply == nullptr) {
		std::cerr << "Redis认证命令发送失败: " << redis_ctx->errstr << std::endl;
		redisFree(redis_ctx);
		return;
	}
	
		// 校验认证结果：成功返回"OK"，失败返回错误信息
	if (!(redis_reply->type == REDIS_REPLY_STATUS && strcasecmp(redis_reply->str, "OK") == 0)) {
		std::cerr << "Redis密码认证失败: " << (redis_reply->str ? redis_reply->str : "未知错误") << std::endl;
		freeReplyObject(redis_reply);  // 释放认证响应
		redisFree(redis_ctx);
		return;
	}
	std::cout << "Redis密码认证成功" << std::endl;
	freeReplyObject(redis_reply);  // 释放认证响应（必须释放，避免内存泄漏）
}
redisContext* Redis::getRedisContext(){
    return this->redis_ctx;
}