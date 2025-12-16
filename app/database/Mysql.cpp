
#include <iostream>
#include <chrono>
#include <mutex>

#include "Mysql.h"
#include "../utils/confRead.h"

//std::string Mysql::_mysql_host = "127.0.0.1";
// std::string Mysql::_mysql_user;// = "zhangyc";
// std::string Mysql::_mysql_pass;// = "zhangyc@APEX!!!";
// std::string Mysql::_mysql_db;// = "cloud_storage";
//int Mysql::_port = 3306;
namespace {
    std::once_flag config_loaded;
}

// void Mysql::setConfig(){
//     std::call_once(config_loaded, []() {
//         ConfigReader config("../../conf/config.env");
//         //_mysql_host = config.get("MYSQL_HOST", "127.0.0.1");
//         _mysql_user = config.get("MYSQL_USER");
//         _mysql_pass = config.get("MYSQL_PASS");
//         _mysql_db   = config.get("MYSQL_DB", "cloud_storage");
//         _port       = config.get_int("MYSQL_PORT", 3306); // 使用前面实现的 get_uint
//     });
// }

Mysql::Mysql(){  
    //setConfig();
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

bool Mysql::beginTransaction(){
    if (conn == nullptr) {
        std::cerr << "[MySQL ERROR] Connection is null when beginning transaction." << std::endl;
        return false;
    }
    if (mysql_autocommit(conn, 0) != 0) {
        std::cerr << "[MySQL ERROR] Failed to set autocommit to 0: " << mysql_error(conn) << std::endl;
        return false;
    }
    return true;
}
bool Mysql::commit(){
    if (conn == nullptr) {
        std::cerr << "[MySQL ERROR] Connection is null when committing." << std::endl;
        return false;
    }
    if (mysql_commit(conn) != 0) {
        std::cerr << "[MySQL ERROR] COMMIT failed: " << mysql_error(conn) << std::endl;
        mysql_autocommit(conn, 1); 
        return false;
    }
    if (mysql_autocommit(conn, 1) != 0) {
        std::cerr << "[MySQL WARN] Failed to set autocommit back to 1: " << mysql_error(conn) << std::endl;
    }

    return true;
}
bool Mysql::rollback(){
    if (conn == nullptr) {
        std::cerr << "[MySQL ERROR] Connection is null when rolling back." << std::endl;
        return false;
    }
    if (mysql_rollback(conn) != 0) {
        std::cerr << "[MySQL ERROR] ROLLBACK failed: " << mysql_error(conn) << std::endl;
        mysql_autocommit(conn, 1); 
        return false;
    }

    // 回滚成功后，恢复自动提交模式
    if (mysql_autocommit(conn, 1) != 0) {
        std::cerr << "[MySQL WARN] Failed to set autocommit back to 1: " << mysql_error(conn) << std::endl;
    }
    return true;
}
//================ CRUD ====================

//for user_info table
bool Mysql::insertUser(const std::string& username, const std::string& password_hash, const std::string& email){
    const char* query = "INSERT INTO user (name, nickname, password, phone, email, createtime) VALUES (?, ?, ?, NULL, ?, ?)";
    MYSQL_STMT* stmt = nullptr; // 声明在 try 块外部，确保在 catch/return 时可以安全访问
    try {
        // 1. 初始化语句句柄
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }   
        // 2. 准备 SQL 语句
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        // --- 时间戳创建 ---
        auto now = std::chrono::system_clock::now();
        auto timet = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        // 注意：std::localtime是非线程安全的，在多线程环境中可能需要使用 std::localtime_r/gmtime_r
        ss << std::put_time(std::localtime(&timet), "%Y-%m-%d %H:%M:%S"); 
        std::string timestamp = ss.str();
        // --- 时间戳创建结束 ---
        // 3. 绑定参数结构
        MYSQL_BIND bind[5] = {};
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(username.c_str());
        bind[0].buffer_length = username.length();

        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = const_cast<char*>(username.c_str());
        bind[1].buffer_length = username.length();
        
        bind[2].buffer_type = MYSQL_TYPE_STRING;
        bind[2].buffer = const_cast<char*>(password_hash.c_str());
        bind[2].buffer_length = password_hash.length();

        bind[3].buffer_type = MYSQL_TYPE_STRING;
        bind[3].buffer = const_cast<char*>(email.c_str());
        bind[3].buffer_length = email.length();
        
        bind[4].buffer_type = MYSQL_TYPE_STRING;
        bind[4].buffer = const_cast<char*>(timestamp.c_str());
        bind[5].buffer_length = timestamp.length();


        // 4. 执行参数绑定
        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        // 5. 执行语句
        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        
        // 6. 清理资源并返回成功
        mysql_stmt_close(stmt);
        return true;

    } catch (const std::runtime_error& e) {
        // 7. 捕获并处理异常
        std::cerr << "[MySQL Error] insertUser failed: " << e.what() << std::endl;
        
        // 8. 确保在出错时关闭语句句柄，避免资源泄漏
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

bool Mysql::getUserPasswordHash(const std::string& username, std::string& out_hash){
	const char* query = "SELECT password FROM user WHERE name = ?";
    MYSQL_STMT* stmt = nullptr;
    
    MYSQL_BIND result_bind[1] = {};
    char hash_buffer[256] = {};
    unsigned long hash_len = sizeof(hash_buffer);
    bool is_null = 0;
    
    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        MYSQL_BIND bind[1] = {};
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(username.c_str());
        bind[0].buffer_length = username.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        result_bind[0].buffer_type = MYSQL_TYPE_STRING;
        result_bind[0].buffer = hash_buffer;
        result_bind[0].buffer_length = sizeof(hash_buffer);
        result_bind[0].length = &hash_len;
        result_bind[0].is_null = &is_null;

        if (mysql_stmt_bind_result(stmt, result_bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_result() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        if (mysql_stmt_store_result(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_store_result() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
    
        if (mysql_stmt_num_rows(stmt) == 0) {
            mysql_stmt_close(stmt);
            return false;
        }

        // 7. 提取第一行结果
        if (mysql_stmt_fetch(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_fetch() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        
        out_hash.assign(hash_buffer, hash_len); 

        mysql_stmt_close(stmt);
        return true;

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] getUserPasswordHash failed: " << e.what() << std::endl;
        
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

bool Mysql::queryUser(const std::string& username){
    const std::string query = "select * from user where name = ?";
    MYSQL_STMT* stmt = nullptr;
    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );}

        MYSQL_BIND bind[1] = {};
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(username.c_str());
        bind[0].buffer_length = username.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );}

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );}

        if (mysql_stmt_store_result(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_store_result() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        bool exists = (mysql_stmt_num_rows(stmt) > 0);

        mysql_stmt_close(stmt);
        
        return exists;
    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] queryUser failed: " << e.what() << std::endl;
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

bool Mysql::queryEmail(const std::string& email){
    const std::string query = "select * from user where email = ?";
    MYSQL_STMT* stmt = nullptr;
    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        if (mysql_stmt_prepare(stmt, query.c_str(), query.length())) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );}

        MYSQL_BIND bind[1] = {};
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(email.c_str());
        bind[0].buffer_length = email.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );}

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );}

        if (mysql_stmt_store_result(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_store_result() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        bool exists = (mysql_stmt_num_rows(stmt) > 0);

        mysql_stmt_close(stmt);
        
        return exists;
    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] queryEmail failed: " << e.what() << std::endl;
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

// for user_file_list table
bool Mysql::insertUserFile(const std::string& md5, const std::string& username, const std::string& filename){
    const char* sql = "INSERT INTO user_file_list (md5, user, filename, createtime) VALUES (?, ?, ?, NOW())";
    MYSQL_STMT* stmt = nullptr; 
    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed."); 
        }
        if (mysql_stmt_prepare(stmt, sql, strlen(sql))) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        MYSQL_BIND bind[3] = {};
        
        bind[0].buffer_type    = MYSQL_TYPE_STRING;
        bind[0].buffer         = (char*)md5.c_str();
        bind[0].buffer_length  = md5.length();

        bind[1].buffer_type    = MYSQL_TYPE_STRING;
        bind[1].buffer         = (char*)username.c_str();
        bind[1].buffer_length  = username.length();
        
        bind[2].buffer_type    = MYSQL_TYPE_STRING;
        bind[2].buffer         = (char*)filename.c_str();
        bind[2].buffer_length  = filename.length();


        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        mysql_stmt_close(stmt);
        return true;

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] insertUserFile failed: " << e.what() << std::endl;
        
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

bool Mysql::isInUserList(const std::string& md5, const std::string& username){
    const char* query = "SELECT 1 FROM user_file_list WHERE md5 = ? AND user = ?";
    MYSQL_STMT* stmt = nullptr;
    MYSQL_RES* res = nullptr;
    bool exists = false;

    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        MYSQL_BIND bind[2] = {};
        
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(md5.c_str());
        bind[0].buffer_length = md5.length();

        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = const_cast<char*>(username.c_str());
        bind[1].buffer_length = username.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        
        res = mysql_stmt_result_metadata(stmt);
        if (res == nullptr) {
             if (mysql_stmt_errno(stmt) != 0) {
                 throw std::runtime_error("mysql_stmt_result_metadata failed: " + std::string(mysql_stmt_error(stmt)));
             }
        }
        
        if (mysql_stmt_store_result(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_store_result() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        if (mysql_stmt_num_rows(stmt) > 0) {
            exists = true;
        }

        mysql_stmt_close(stmt);
        
        return exists;

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] isInUserList failed: " << e.what() << std::endl;
        if (stmt) {
            mysql_stmt_close(stmt);
        }

        return false;
    }
}

bool Mysql::deleteUserFile(const std::string& username, const std::string& md5){
    bool success = false;
    const char* sql = "DELETE FROM user_file_list WHERE user = ? AND md5 = ?";
    MYSQL_STMT* stmt = nullptr;
    try {

        stmt = mysql_stmt_init(conn);
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
        std::cerr << "[MySQL Error] deleteUserFile failed: " << e.what() << std::endl;
        return false;
    }
}

// for file_info table
bool Mysql::insertFileInfo(const std::string& md5, const std::string& url, const std::string& type){
    // 1. 定义 SQL 语句：使用 INSERT ... ON DUPLICATE KEY UPDATE 实现计数逻辑
    //    如果 md5 冲突，则将 count 字段 +1。
    const char* query = 
        "INSERT INTO file_info (md5, url, count, type) "
        "VALUES (?, ?, 1, ?) "
        "ON DUPLICATE KEY UPDATE count = count + 1";
        
    MYSQL_STMT* stmt = nullptr;

    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        MYSQL_BIND bind[3] = {};
        
        bind[0].buffer_type    = MYSQL_TYPE_STRING;
        bind[0].buffer         = const_cast<char*>(md5.c_str());
        bind[0].buffer_length  = md5.length();

        bind[1].buffer_type    = MYSQL_TYPE_STRING;
        bind[1].buffer         = const_cast<char*>(url.c_str());
        bind[1].buffer_length  = url.length();
        
        bind[2].buffer_type    = MYSQL_TYPE_STRING;
        bind[2].buffer         = const_cast<char*>(type.c_str());
        bind[2].buffer_length  = type.length();


        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        
        mysql_stmt_close(stmt);
        return true;

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] insertFileInfo failed: " << e.what() << std::endl;

        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }

}

bool Mysql::isInMySQL(const std::string& md5){
    const char* query = "SELECT url FROM file_info WHERE md5 = ?";
    MYSQL_STMT* stmt = nullptr;

    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        
        if (mysql_stmt_prepare(stmt, query, strlen(query))) {
            throw std::runtime_error(
                "mysql_stmt_prepare() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        MYSQL_BIND bind[1] = {};
        
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = const_cast<char*>(md5.c_str());
        bind[0].buffer_length = md5.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error(
                "mysql_stmt_bind_param() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_execute() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }
        
        if (mysql_stmt_store_result(stmt)) {
            throw std::runtime_error(
                "mysql_stmt_store_result() failed: " + std::string(mysql_stmt_error(stmt))
            );
        }

        bool exists = (mysql_stmt_num_rows(stmt) > 0);

        mysql_stmt_close(stmt);
        
        return exists;

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] isInMySQL failed: " << e.what() << std::endl;
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

bool Mysql::deleteSysFile(const std::string& md5){
    bool success = false;
    const char* sql = "DELETE FROM file_info WHERE md5 = ?";
    MYSQL_STMT* stmt = nullptr;
    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            std::cerr << "mysql_stmt_init() failed" << std::endl;
            return false;
        }

        if (mysql_stmt_prepare(stmt, sql, strlen(sql))) {
            std::cerr << "mysql_stmt_prepare() failed: " << mysql_stmt_error(stmt) << std::endl;
            mysql_stmt_close(stmt);
            return false;
        }

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
        std::cerr << "[MySQL Error] deleteSysFile failed: " << e.what() << std::endl;
        return false;
    }
}

void Mysql::queryUserFiles(const std::string& username, nlohmann::json& array){
    const char* sql = R"(
        SELECT user_file_list.md5, user_file_list.filename, file_info.url 
        FROM user_file_list
        INNER JOIN file_info ON user_file_list.md5 = file_info.md5
        WHERE user_file_list.user = ?
    )";

    MYSQL_STMT* stmt = nullptr;
    
    char md5_buffer[33] = {0};
    char filename_buffer[256] = {0}; 
    char url_buffer[512] = {0}; 
    unsigned long md5_len, filename_len, url_len;
    bool md5_is_null, filename_is_null, url_is_null;

    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("mysql_stmt_init() failed.");
        }
        
        if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            throw std::runtime_error("SQL预处理失败: " + std::string(mysql_stmt_error(stmt)));
        }

        MYSQL_BIND param_bind{};
        param_bind.buffer_type = MYSQL_TYPE_STRING;
        param_bind.buffer = (char*)username.c_str();
        param_bind.buffer_length = username.size();
        
        if (mysql_stmt_bind_param(stmt, &param_bind) != 0) {
            throw std::runtime_error("参数绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }
        if (mysql_stmt_execute(stmt) != 0) {
            throw std::runtime_error("查询失败: " + std::string(mysql_stmt_error(stmt)));
        }

        MYSQL_BIND result_bind[3]{};
        
        // 绑定 md5 (0)
        result_bind[0].buffer_type = MYSQL_TYPE_STRING;
        result_bind[0].buffer = md5_buffer;
        result_bind[0].buffer_length = sizeof(md5_buffer);
        result_bind[0].length = &md5_len;
        result_bind[0].is_null = &md5_is_null;
        
        result_bind[1].buffer_type = MYSQL_TYPE_STRING;
        result_bind[1].buffer = filename_buffer;
        result_bind[1].buffer_length = sizeof(filename_buffer);
        result_bind[1].length = &filename_len;
        result_bind[1].is_null = &filename_is_null;

        result_bind[2].buffer_type = MYSQL_TYPE_STRING;
        result_bind[2].buffer = url_buffer;
        result_bind[2].buffer_length = sizeof(url_buffer);
        result_bind[2].length = &url_len;
        result_bind[2].is_null = &url_is_null;

        if (mysql_stmt_bind_result(stmt, result_bind) != 0) {
            throw std::runtime_error("结果集绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }
        
        if (mysql_stmt_store_result(stmt) != 0) {
             throw std::runtime_error("存储结果集失败: " + std::string(mysql_stmt_error(stmt)));
        }

        while (mysql_stmt_fetch(stmt) == 0) {
            nlohmann::json fileItem;

            fileItem["id"] = std::string(md5_buffer, md5_len);
            fileItem["filename"] = std::string(filename_buffer, filename_len);
            fileItem["url"] = std::string(url_buffer, url_len);
            
            array.push_back(fileItem);
        }

        mysql_stmt_close(stmt);

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] queryUserFiles failed: " << e.what() << std::endl;
        
        if (stmt) {
            mysql_stmt_close(stmt);
        }

        throw;
    }
}

bool Mysql::updateCount(const std::string& md5, int delta){
    bool success = false;
    MYSQL_STMT* stmt = nullptr;

    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("创建stmt句柄失败: " + std::string(mysql_error(conn)));
        }

        const char* sql = "UPDATE file_info SET count = count + ? WHERE md5 = ?";
        if (mysql_stmt_prepare(stmt, sql, strlen(sql)) != 0) {
            throw std::runtime_error("SQL预处理失败: " + std::string(mysql_stmt_error(stmt)));
        }

        MYSQL_BIND param_bind[2] = {};
        param_bind[0].buffer_type = MYSQL_TYPE_LONG;
        param_bind[0].buffer = &delta;
        param_bind[0].is_unsigned = false;
        param_bind[0].length = nullptr;

        param_bind[1].buffer_type = MYSQL_TYPE_STRING;
        param_bind[1].buffer = const_cast<char*>(md5.c_str());
        param_bind[1].buffer_length = md5.size();
        param_bind[1].length = &param_bind[1].buffer_length;
        param_bind[1].is_unsigned = false;

        if (mysql_stmt_bind_param(stmt, param_bind) != 0) {
            throw std::runtime_error("参数绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        if (mysql_stmt_execute(stmt) != 0) {
            throw std::runtime_error("count更新执行失败: " + std::string(mysql_stmt_error(stmt)));
        }

        my_ulonglong affected_rows = mysql_stmt_affected_rows(stmt);
        if (affected_rows == 0) {
            throw std::runtime_error("未找到md5=" + md5 + "的记录，更新无生效");
        }

        success = true;

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] Failed to update count" << e.what() << std::endl;
        success = false;
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
    if (stmt) {
        mysql_stmt_close(stmt);
    }
    return success;
}


bool Mysql::getCount(const std::string& md5, int& count, std::string& url){
    const char* sql = "SELECT count, url FROM file_info WHERE md5 = ?";
    MYSQL_STMT* stmt = nullptr;
    
    // 输出参数缓冲区和长度变量声明
    char url_buffer[512] = {0}; 
    unsigned long url_len = 0;
    bool is_null[2] = {0}; // 两个字段，count和url

    try {
        stmt = mysql_stmt_init(conn);
        if (!stmt) {
            throw std::runtime_error("创建stmt句柄失败: " + std::string(mysql_error(conn)));
        }
        
        if (mysql_stmt_prepare(stmt, sql, strlen(sql))) {
            throw std::runtime_error("SQL预处理失败: " + std::string(mysql_stmt_error(stmt)));
        }

        MYSQL_BIND bind[1] = {};
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = (char*)md5.c_str();
        bind[0].buffer_length = md5.length();

        if (mysql_stmt_bind_param(stmt, bind)) {
            throw std::runtime_error("参数绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        if (mysql_stmt_execute(stmt)) {
            throw std::runtime_error("查询执行失败: " + std::string(mysql_stmt_error(stmt)));
        }
        
        if (mysql_stmt_store_result(stmt)) {
            throw std::runtime_error("存储结果集失败: " + std::string(mysql_stmt_error(stmt)));
        }
        
        MYSQL_BIND result[2] = {};
        // 结果1: count (整数)
        result[0].buffer_type = MYSQL_TYPE_LONG;
        result[0].buffer = &count;
        result[0].is_null = &is_null[0];
        
        result[1].buffer_type = MYSQL_TYPE_STRING;
        result[1].buffer = url_buffer;
        result[1].buffer_length = sizeof(url_buffer);
        result[1].length = &url_len;
        result[1].is_null = &is_null[1];

        if (mysql_stmt_bind_result(stmt, result)) {
            throw std::runtime_error("结果绑定失败: " + std::string(mysql_stmt_error(stmt)));
        }

        int fetch_ret = mysql_stmt_fetch(stmt);
        
        if (fetch_ret == 0) {
            if (is_null[1]) {
                url.clear();
            } else {
                url.assign(url_buffer, url_len);
            }
            std::cout << "[MySQL INFO] Get count: " << count << std::endl;
            mysql_stmt_close(stmt);
            return true;
            
        } else if (fetch_ret == MYSQL_NO_DATA) {
            std::cerr << "[MySQL WARN] No data found for md5: " << md5 << std::endl;
            // 未找到路径：清理资源
            mysql_stmt_close(stmt);
            return false;
            
        } else {
            throw std::runtime_error("Fetch failed: " + std::string(mysql_stmt_error(stmt)));
        }

    } catch (const std::runtime_error& e) {
        std::cerr << "[MySQL Error] getCount failed: " << e.what() << std::endl;
        
        // 异常路径：确保清理资源
        if (stmt) {
            mysql_stmt_close(stmt);
        }
        return false;
    }
}

