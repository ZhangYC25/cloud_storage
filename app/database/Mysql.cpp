
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
            std::cout << "Debug: Successfully created new connection." << std::endl;
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
        std::cout << "成功向user_file_list插入记录,md5: " << md5 << ", 用户名: " << username << std::endl;

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

bool Mysql::addCount(const std::string& md5){
    int ret = 0;
    bool success = false;
    try{
        ret = mysql_query(conn, "START TRANSACTION");
        if (ret != 0) {
            throw std::runtime_error("开启事务失败: " + std::string(mysql_error(conn)));
        }

        const char* sql = "UPDATA file_info SET count = count + 1 WHERE md5 = ?";    
        
        // 3. 预处理SQL + 绑定参数（防止注入，不变）
        MYSQL_STMT* stmt = mysql_stmt_init(conn);
        if (!stmt || mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            throw std::runtime_error("SQL预处理失败: " + std::string(mysql_error(conn)));
        }

        // 绑定currentUser参数
        MYSQL_BIND param_bind{};
        param_bind.buffer_type = MYSQL_TYPE_STRING;
        param_bind.buffer = (char*)md5.c_str();
        param_bind.buffer_length = md5.size();
        if (mysql_stmt_bind_param(stmt, &param_bind) != 0) {
            throw std::runtime_error("参数绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        if (mysql_stmt_execute(stmt) == 0) {
            //throw std::runtime_error("count+1失败: " + std::string(mysql_stmt_error(stmt)));
            success = true;
            mysql_stmt_close(stmt);
            return success;
        }
        throw std::runtime_error("count+1失败: " + std::string(mysql_stmt_error(stmt)));
        return success;
    }catch(const std::runtime_error& e){
        std::cerr << "Failed to increment count for md5=" << md5 
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
                                        "VALUES ('" + md5 + "','" + url + "', 1) "
                                        "ON DUPLICATE KEY UPDATE count = count + 1";
        ret = mysql_query(conn, updateFileInfoSql.c_str());
        if (ret != 0) {
            throw std::runtime_error("更新file_info count失败: " + std::string(mysql_error(conn)));
        }
        std::cout << "成功更新file_info表,md5: " << md5 << "的count字段+1" << std::endl;

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

