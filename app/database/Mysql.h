#pragma once

#include <string>
#include <iostream>

#include <mysql/mysql.h>
#include <cstring>
#include <iomanip>

class Mysql
{
public:

    //连接与销毁
    Mysql();
    ~Mysql();
    

    //获得数据库的信息
    std::string getPassword() const;
    std::string getUserinfo() const;
    std::string getDatabase() const;
    int getPort() const;

    MYSQL* getConn();
// =========== 实现增删查改 ==============
    // for user_info table
    bool insertUser(const std::string& username, const std::string& password_hash);
    bool getUserPasswordHash(const std::string& username, std::string& out_hash);

    // for user_file_list table
    bool insertUserFile(const std::string& md5, const std::string& username, const std::string& filename);
    bool isInUserList(const std::string& md5, const std::string& username);

    // for file_info table
    bool insertFileInfo(const std::string& md5, const std::string& url);
    bool isInMySQL(const std::string& md5);
// ============= end ===================

private:
    const std::string _mysql_host = "127.0.0.1";
    const std::string _mysql_user = "zhangyc";
    const std::string _mysql_pass = "zhangyc@APEX!!!";
    const std::string _mysql_db = "cloud_storage";
    unsigned int _port = 3306;

    MYSQL* conn;

};
