#include <stdio.h>
#include <stdlib.h>  // 新增：用于打印错误
#include "hiredis.h"

int main() {
    // 1. 连接Redis，打印连接错误
    redisContext* c = redisConnect("127.0.0.1", 6379);
    if (c == NULL || c->err != 0) {
        if (c) {
            printf("连接Redis失败: %s\n", c->errstr);  // 显示具体错误（如拒绝连接、认证失败）
            redisFree(c);
        } else {
            printf("连接Redis失败: 内存分配错误\n");
        }
        return -1;
    }
    printf("Redis连接成功！\n");  // 确认连接成功

    // 2. 执行认证（关键步骤：替换为你的Redis密码）
    const char* redis_password = "ZYCzyc520@APEX!";  // 这里替换为你的实际密码
    redisReply* ply = (redisReply*)redisCommand(c, "AUTH %s", redis_password);
    if (ply == NULL) {
        printf("认证命令执行失败: %s\n", c->errstr);
        redisFree(c);
        return -1;
    }
    // 2. 执行hmset命令，检查返回值
    ply = (redisReply*)redisCommand(c, "hmset user userName zhang3 passwd 123456 age 23 sex man");
    if (ply == NULL) {
        printf("hmset执行失败: %s\n", c->errstr);  // 命令失败原因
        redisFree(c);
        return -1;
    }
    // 用宏判断类型，更可靠
    if (ply->type == REDIS_REPLY_STATUS) {
        printf("hmset状态: %s\n", ply->str);  // 预期输出 "OK"
    } else {
        printf("hmset返回非预期类型: %d（可能是错误）\n", ply->type);
        if (ply->type == REDIS_REPLY_ERROR) {
            printf("错误信息: %s\n", ply->str);  // 显示Redis返回的错误
        }
    }
    freeReplyObject(ply);

    // 3. 执行hgetall命令，同样检查返回值
    ply = (redisReply*)redisCommand(c, "hgetall user");
    if (ply == NULL) {
        printf("hgetall执行失败: %s\n", c->errstr);
        redisFree(c);
        return -1;
    }
    if (ply->type == REDIS_REPLY_ARRAY) {
        printf("hgetall结果（共%d个元素）:\n", (int)ply->elements);
        for (int i = 0; i < ply->elements; i += 2) {
            printf("key: %s, value: %s\n", ply->element[i]->str, ply->element[i+1]->str);
        }
    } else {
        printf("hgetall返回非预期类型: %d\n", ply->type);
        if (ply->type == REDIS_REPLY_ERROR) {
            printf("错误信息: %s\n", ply->str);
        }
    }
    freeReplyObject(ply);

    redisFree(c);
    return 0;
}
