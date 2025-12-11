
#include "Mysql.h"

#include <iostream>
#include <chrono>

Mysql::Mysql(){  
            conn = mysql_init(nullptr);
            if (!conn) {
                std::cerr << "Error: mysql_init failed." << std::endl;
                return;
            }
            // 尝试连接数据库
            if (mysql_real_connect(conn, _mysql_host.c_str(), _mysql_user.c_str(), _mysql_pass.c_str(),
                           _mysql_db.c_str(), _port, nullptr, 0) == nullptr) {
                std::cerr << "Error: mysql_real_connect failed: " << mysql_error(conn) << std::endl;
                mysql_close(conn);
                return;
            }
            //std::cout << "Debug: Successfully created new connection." << std::endl;
            };

Mysql::~Mysql() {
    if (conn) {
        mysql_close(conn);
        //printf("Mysql 连接释放，_rawConn: %p\n", _rawConn);
        conn = nullptr;
    }
}

MYSQL* Mysql::getConn(){return conn;}

//================ CRUD ====================

//for user_info table
bool Mysql::insertUser(const std::string& username, const std::string& password_hash){

	const char* query = "INSERT INTO user (name, nickname, password, phone, email, createtime) VALUE (?, ?, ?, NULL, NULL, ?)";
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, query, strlen(query))) {
		std::cerr << "Prepare failed" << std::endl;
		if (stmt) mysql_stmt_close(stmt);
		return false;
	}
	//create current time
	auto now = std::chrono::system_clock::now();
	auto timet = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&timet), "%Y-%m-%d %H:%M:%S");
	std::string timestamp = ss.str();
	//bind sql characteriaze
	MYSQL_BIND bind[4] = {};
	//name
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = const_cast<char*>(username.c_str());
	bind[0].buffer_length = username.length();

	//nickname = name
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = const_cast<char*>(username.c_str());
	bind[1].buffer_length = username.length();
	
	//password
	bind[2].buffer_type = MYSQL_TYPE_STRING;
	bind[2].buffer = const_cast<char*>(password_hash.c_str());
	bind[2].buffer_length = password_hash.length();
	
	//createtimr
	bind[3].buffer_type = MYSQL_TYPE_STRING;
	bind[3].buffer = const_cast<char*>(timestamp.c_str());
	bind[3].buffer_length = timestamp.length();

	//if success return 0
	if (mysql_stmt_bind_param(stmt, bind)) {
		std::cerr << "Bind param failed: " << mysql_stmt_error(stmt) << std::endl;
		mysql_stmt_close(stmt);
		return false;
	}

	// if success return 0;
	bool success = !mysql_stmt_execute(stmt);
	mysql_stmt_close(stmt);
	return success;
}

bool Mysql::getUserPasswordHash(const std::string& username, std::string& out_hash){
	const char* query = "SELECT password FROM user WHERE name = ?";
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt || mysql_stmt_prepare(stmt, query, strlen(query))) {
		std::cerr << "Prepare failed" << std::endl;
		if (stmt) mysql_stmt_close(stmt);
        	return false;
	}
	
	MYSQL_BIND bind[1] = {};
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = const_cast<char*>(username.c_str());
	bind[0].buffer_length = username.length();

	if (mysql_stmt_bind_param(stmt, bind)) {
		std::cerr << "Bind param failed" << std::endl;
       		mysql_stmt_close(stmt);
        	return false;
	}

	if (mysql_stmt_execute(stmt)) {
		std::cerr << "Execute error: " << std::endl;
		mysql_stmt_close(stmt);
		return false;
	}

	MYSQL_BIND result_bind[1] = {};
	char hash_buffer[256];
	unsigned long hash_len = sizeof(hash_buffer);
	bool is_null = 0;

	result_bind[0].buffer_type = MYSQL_TYPE_STRING;
	result_bind[0].buffer = hash_buffer;	
	result_bind[0].buffer_length = hash_len;
	result_bind[0].length = &hash_len;
	result_bind[0].is_null = &is_null;

	//bind result || store result || fetch result
	if (mysql_stmt_bind_result(stmt, result_bind) ||
		mysql_stmt_store_result(stmt) ||
        	mysql_stmt_fetch(stmt)) {
        	mysql_stmt_close(stmt);
        	return false;
	}

	out_hash = std::string(hash_buffer, hash_len);
	mysql_stmt_close(stmt);
	return true;
}

//bool Mysql::queryUser(const std::string& username){}

// for user_file_list table
bool Mysql::insertUserFile(const std::string& md5, const std::string& username, const std::string& filename){
    int ret = 0;
    bool result = false;

    try {
        // 3. 开启事务（保证插入和更新操作的原子性）
        ret = mysql_query(conn, "START TRANSACTION");
        if (ret != 0) {
            throw std::runtime_error("开启事务失败: " + std::string(mysql_error(conn)));
        }

        // 4. 向user_file_list表插入记录
        // 拼接SQL（注意：生产环境必须用预处理语句防注入，此处先按需求实现基础功能）
        std::string insertUserSql = "INSERT INTO user_file_list (md5, user, filename, createtime) "
                                    "VALUES ('" + md5 + "', '" + username + "', '" + filename + "', NOW())";
        ret = mysql_query(conn, insertUserSql.c_str());
        if (ret != 0) {
            throw std::runtime_error("插入user_file_list失败: " + std::string(mysql_error(conn)));
        }
        //std::cout << "成功向user_file_list插入记录,md5: " << md5 << ", 用户名: " << username << std::endl;

        // 6. 提交事务
        ret = mysql_query(conn, "COMMIT");
        if (ret != 0) {
            throw std::runtime_error("提交事务失败: " + std::string(mysql_error(conn)));
        }
        result = true; // 所有操作成功

    } catch (const std::runtime_error& e) {
        // 7. 出错时回滚事务
        std::cerr << "操作失败，回滚事务: " << e.what() << std::endl;
        mysql_query(conn, "ROLLBACK");
        result = false;
    }

    // 8. 释放数据库资源
    return result;
}

bool Mysql::isInUserList(const std::string& md5, const std::string& username){
	std::string query = "SELECT 1 FROM user_file_list WHERE md5 = '" + md5 + "' and user = '" + username + "'";
	
	int query_ret = mysql_query(conn, query.c_str());
    if (query_ret != 0) { // 非0表示查询失败
        std::cerr << "isInUserList Query error: " << mysql_error(conn) << std::endl;
        return false;
    }

    MYSQL_RES* res = mysql_store_result(conn);
    if (res == nullptr) {
        std::cerr << "mysql_store_result failed: " << mysql_error(conn) << std::endl;
        return false;
    }

    bool exists = false;
    // 6. 读取行：若有行则表示记录存在
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row != nullptr) {
        exists = true;
    }

    mysql_free_result(res);
    return exists;
}

bool Mysql::deleteUserFile(const std::string& username, const std::string& md5){
    bool success = false;
    try {
        const char* sql = "DELETE FROM user_file_list WHERE user = ? AND md5 = ?";

        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt) {
            std::cerr << "mysql_stmt_init() failed" << std::endl;
            return false;
        }

        if (mysql_stmt_prepare(stmt, sql, strlen(sql))) {
            std::cerr << "mysql_stmt_prepare() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

        // 绑定参数
        MYSQL_BIND bind[2] = {};

        // username
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)username.c_str();
        bind[0].buffer_length = username.length();

        // md5
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = (char*)md5.c_str();
        bind[1].buffer_length = md5.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            std::cerr << "mysql_stmt_bind_param() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

        if (mysql_stmt_execute(stmt)) {
            std::cerr << "mysql_stmt_execute() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

        mysql_stmt_close(stmt);
        success = true;
        return success;
    } catch ( const std::runtime_error& e) {
        std::cerr << "Failed to delete file for md5=" << md5 
                  << ": " << e.what() << std::endl;
        throw; // 或根据需求处理
    }
}

// for file_info table
bool Mysql::insertFileInfo(const std::string& md5, const std::string& url){
    int ret = 0;
    bool result = false;

    try {
        // 3. 开启事务（保证插入和更新操作的原子性）
        ret = mysql_query(conn, "START TRANSACTION");
        if (ret != 0) {
            throw std::runtime_error("开启事务失败: " + std::string(mysql_error(conn)));
        }

        // 4. 更新file_info表 (存在则+1，不存在则初始化count=1）
        // 使用INSERT ... ON DUPLICATE KEY UPDATE实现「存在更新，不存在插入」
        std::string updateFileInfoSql = "INSERT INTO file_info (md5, url, count) "
                                        "VALUES ('" + md5 + "','" + url + "', 1) ";
        ret = mysql_query(conn, updateFileInfoSql.c_str());
        if (ret != 0) {
            throw std::runtime_error("更新file_info count失败: " + std::string(mysql_error(conn)));
        }
        //std::cout << "成功插入file_info表,md5: " << md5 << std::endl;

        // 6. 提交事务
        ret = mysql_query(conn, "COMMIT");
        if (ret != 0) {
            throw std::runtime_error("提交事务失败: " + std::string(mysql_error(conn)));
        }
        result = true; // 所有操作成功

    } catch (const std::runtime_error& e) {
        // 7. 出错时回滚事务
        std::cerr << "操作失败，回滚事务: " << e.what() << std::endl;
        mysql_query(conn, "ROLLBACK");
        result = false;
    }

    // 8. 释放数据库资源
    return result;

}

bool Mysql::isInMySQL(const std::string& md5){
    // 构造查询SQL（注意：生产环境建议用预处理语句防SQL注入）
    std::string query = "SELECT 1 FROM file_info WHERE md5 = '" + md5 + "'";

    // 执行SQL语句，用int接收执行结果
    int query_ret = mysql_query(conn, query.c_str());
    bool exists = false; // 变量名修正：exits -> exists（笔误）

    if (query_ret != 0) {
        std::cerr << "Query error: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return exists;
    }

    // 关键：获取查询结果集（MYSQL_RES*类型）
    MYSQL_RES* res = mysql_store_result(conn);
    if (res == nullptr) {
        std::cerr << "mysql_store_result error: " << mysql_error(conn) << std::endl;
        mysql_close(conn);
        return exists;
    }

    // 从结果集中获取行数据
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row != nullptr) {
        exists = true; // 查到数据则标记为存在
    }

    // 释放结果集资源（必须调用，避免内存泄漏）
    mysql_free_result(res);

    return exists;
}

bool Mysql::deleteSysFile(const std::string& md5){
    bool success = false;
    try {
        const char* sql = "DELETE FROM file_info WHERE md5 = ?";

        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt) {
            std::cerr << "mysql_stmt_init() failed" << std::endl;
            return false;
        }

        if (mysql_stmt_prepare(stmt, sql, strlen(sql))) {
            std::cerr << "mysql_stmt_prepare() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

        // 绑定参数
        MYSQL_BIND bind[1] = {};
        // md5
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)md5.c_str();
        bind[0].buffer_length = md5.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            std::cerr << "mysql_stmt_bind_param() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

        if (mysql_stmt_execute(stmt)) {
            std::cerr << "mysql_stmt_execute() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

        mysql_stmt_close(stmt);
        success = true;
        return success;
    } catch ( const std::runtime_error& e) {
        std::cerr << "Failed to delete file for md5=" << md5 
                  << ": " << e.what() << std::endl;
        throw; // 或根据需求处理
    }
}

void Mysql::queryUserFiles(const std::string& username, nlohmann::json& array){
    // 2. 联表查询SQL（不变）
        const char* sql = R"(
            SELECT user_file_list.md5, user_file_list.filename, file_info.url 
            FROM user_file_list
            INNER JOIN file_info ON user_file_list.md5 = file_info.md5
            WHERE user_file_list.user = ?
        )";

        // 3. 预处理SQL + 绑定参数（防止注入，不变）
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            throw std::runtime_error("SQL预处理失败: " + std::string(mysql_error(conn)));
        }

        // 绑定currentUser参数
        MYSQL_BIND param_bind{};
        param_bind.buffer_type = MYSQL_TYPE_STRING;
        param_bind.buffer = (char*)username.c_str();
        param_bind.buffer_length = username.size();
        if (mysql_stmt_bind_param(stmt, &param_bind) != 0) {
            throw std::runtime_error("参数绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        // 4. 执行查询
        if (mysql_stmt_execute(stmt) != 0) {
            throw std::runtime_error("查询失败: " + std::string(mysql_stmt_error(stmt)));
        }

        // 5. 绑定结果集（只绑定前端需要的字段：md5(id)、filename、url）
        // 注意：需要先分配足够的缓冲区，这里用动态数组避免长度问题
        char md5[33] = {0};       // md5固定32位，加1存结束符
        char filename[256] = {0}; // 文件名缓冲区
        char url[512] = {0};      // 文件URL缓冲区

        MYSQL_BIND result_bind[3]{};
        // 绑定md5（对应SELECT的第一个字段，作为前端的id）
        result_bind[0].buffer_type = MYSQL_TYPE_STRING;
        result_bind[0].buffer = md5;
        result_bind[0].buffer_length = sizeof(md5);
        // 绑定filename（第二个字段）
        result_bind[1].buffer_type = MYSQL_TYPE_STRING;
        result_bind[1].buffer = filename;
        result_bind[1].buffer_length = sizeof(filename);
        // 绑定url（第三个字段）
        result_bind[2].buffer_type = MYSQL_TYPE_STRING;
        result_bind[2].buffer = url;
        result_bind[2].buffer_length = sizeof(url);

        if (mysql_stmt_bind_result(stmt, result_bind) != 0) {
            throw std::runtime_error("结果集绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        // 6. 遍历结果，直接组装JSON（核心：不用结构体，直接拼JSON）
        while (mysql_stmt_fetch(stmt) == 0) {
            // 临时JSON对象，存储一行数据
            nlohmann::json fileItem;
            fileItem["id"] = md5;          // 前端delete需要的唯一标识
            fileItem["filename"] = filename; // 文件名
            fileItem["url"] = url;         // 文件访问链接
            array.push_back(fileItem); // 加入数组
        }

        // 7. 释放资源
        mysql_stmt_close(stmt);
}

bool Mysql::updateCount(const std::string& md5, int delta){
    bool success = false;
    MYSQL_STMT* stmt = nullptr; // 提前声明stmt，确保最终能释放

    try {
        // 1. 初始化预处理语句句柄
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("创建stmt句柄失败: " + std::string(mysql_error(conn)));
        }

        // 2. 预处理SQL（仅更新count，支持正负delta）
        const char* sql = "UPDATE file_info SET count = count + ? WHERE md5 = ?";    
        if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            throw std::runtime_error("SQL预处理失败: " + std::string(mysql_error(conn)));
        }

        // 3. 绑定参数（delta支持正数/负数，md5字符串完整绑定）
        MYSQL_BIND param_bind[2] = {};
        // 参数1：delta（整数类型，支持-1、1等任意整数值）
        param_bind[0].buffer_type = MYSQL_TYPE_LONG;
        param_bind[0].buffer = &delta;
        param_bind[0].is_unsigned = false;
        param_bind[0].length = nullptr;

        // 参数2：md5字符串（必须指定长度，避免截断导致匹配失败）
        param_bind[1].buffer_type = MYSQL_TYPE_STRING;
        param_bind[1].buffer = const_cast<char*>(md5.c_str()); // 强制转换（无修改，安全）
        param_bind[1].buffer_length = md5.size();
        param_bind[1].length = &param_bind[1].buffer_length;
        param_bind[1].is_unsigned = false;

        if (mysql_stmt_bind_param(stmt, param_bind) != 0) {
            throw std::runtime_error("参数绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        // 4. 执行更新操作
        if (mysql_stmt_execute(stmt) != 0) {
            throw std::runtime_error("count更新执行失败: " + std::string(mysql_stmt_error(stmt)));
        }

        // 5. 检查受影响行数（确认是否真的更新了记录）
        my_ulonglong affected_rows = mysql_stmt_affected_rows(stmt);
        if (affected_rows == 0) {
            throw std::runtime_error("未找到md5=" + md5 + "的记录，更新无生效");
        }

        // 所有步骤成功，标记为true
        success = true;
    } catch (const std::runtime_error& e) {
        // 打印错误日志，不吞异常（上层可捕获）
        std::cerr << "Failed to update count for md5=" << md5 
                  << ": " << e.what() << std::endl;
        success = false;
        throw; // 抛出异常，让上层事务统一处理回滚/重试
    }
    return success;
}


bool Mysql::getCount(const std::string& md5, int& count, std::string& url){
    const char* sql = "SELECT count,url FROM file_info WHERE md5 = ?";
    MYSQL_STMT* stmt = mysql_stmt_init(conn);
    if (mysql_stmt_prepare(stmt, sql, strlen(sql))) {
        std::cerr << "Prepare failed: " << mysql_stmt_error(stmt) << std::endl;
        mysql_stmt_close(stmt);
        return false;
    }
    MYSQL_BIND bind[1] = {};
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = (char*)md5.c_str();
    bind[0].buffer_length = md5.length();

    if (mysql_stmt_bind_param(stmt, bind)) {
        std::cerr << "Bind param failed" << std::endl;
        mysql_stmt_close(stmt);
        return false;
    }

    if (mysql_stmt_execute(stmt)) {
        std::cerr << "Execute failed" << std::endl;
        mysql_stmt_close(stmt);
        return false;
    }

    MYSQL_BIND result[2] = {};
    result[0].buffer_type = MYSQL_TYPE_LONG;
    result[0].buffer = &count;

    // 输出参数2：url（字符串，核心修复）
    char url_buffer[512] = {0}; // 定义足够大的缓冲区（根据实际URL长度调整）
    result[1].buffer_type = MYSQL_TYPE_STRING;
    result[1].buffer = url_buffer; // 绑定到可写的缓冲区
    result[1].buffer_length = sizeof(url_buffer); // 指定缓冲区大小
    unsigned long url_len = 0;
    result[1].length = &url_len; // 接收实际返回的URL长度（避免截断）

    if (mysql_stmt_bind_result(stmt, result)) {
        std::cerr << "Bind result failed" << std::endl;
        mysql_stmt_close(stmt);
        return false;
    }

    // 5. 读取结果（处理返回值，区分正常/异常）
    int fetch_ret = mysql_stmt_fetch(stmt);
    if (fetch_ret == 0) {
        // 读取成功：将缓冲区内容赋值给url（解决乱码）
        url = std::string(url_buffer, url_len); // 按实际长度赋值，避免多余空字符
        std::cout << "[MySQL INFO] Get count: " << count << std::endl;
        mysql_stmt_close(stmt);
        return true;
    } else if (fetch_ret == MYSQL_NO_DATA) {
        // 无数据（md5不存在）
        std::cerr << "[MySQL WARN] No data found for md5: " << md5 << std::endl;
        mysql_stmt_close(stmt);
        return false;
    } else {
        // fetch失败
        std::cerr << "Fetch failed: " << mysql_stmt_error(stmt) << std::endl;
        mysql_stmt_close(stmt);
        return false;
    }
}

