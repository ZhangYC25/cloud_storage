cmake_minimum_required(VERSION 3.14)
project(cloud_storage_server VERSION 1.0 LANGUAGES CXX)

# 使用C++17标准（Pistache依赖）
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 默认构建类型为Debug（可通过-DCMAKE_BUILD_TYPE=Release切换）
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# ========== 1. 头文件路径配置 ==========
# 项目自身头文件（当前目录下的所有子目录）
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}          # 根目录（main.cpp所在）
    ${CMAKE_CURRENT_SOURCE_DIR}/database # database子目录
    ${CMAKE_CURRENT_SOURCE_DIR}/myfastdfs # myfastdfs子目录
    ${CMAKE_CURRENT_SOURCE_DIR}/server
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
)

# 系统/第三方头文件
include_directories(
    /usr/local/include                   # Pistache头文件
    /usr/include/mysql                   # MySQL头文件
    /usr/include/fastcommon              # fastcommon头文件
    /usr/include/fastdfs                 # fastdfs头文件
    /usr/local/include/bcrypt   # bcrypt头文件
    /usr/include/x86_64-linux-gnu #curl
    /home/zhangyc/tencentcloud-sdk-cpp/core/include
)

# ========== 2. 库路径配置（可选，若库不在系统默认路径） ==========
# 示例：若Pistache是手动编译到自定义路径，需添加
# link_directories(/home/zhangyc/fastdfs-nginx/pistache/build/src)

# ========== 3. 源文件配置（把所有.cpp文件加入） ==========
set(SOURCES
    main.cpp
    server/server.cpp
    server/api.cpp
    server/session.cpp
    server/email.cpp
    # database子目录下的源文件
    database/Mysql.cpp
    database/mysqlConnPool.cpp
    database/redis.cpp
    database/redisConnPool.cpp
    # myfastdfs子目录下的源文件
    myfastdfs/fdfsClient.cpp
    myfastdfs/fdfsConnPool.cpp
    utils/confRead.cpp
    utils/asyncLogger.cpp
    utils/threadPool.cpp
)


# ========== 4. 生成可执行文件 ==========
add_executable(cloud_storage_server ${SOURCES})


# ========== 5. 链接库 ==========
target_link_libraries(cloud_storage_server
    PRIVATE
        mysqlclient         # MySQL动态库
        pistache            # Pistache动态库
        ssl                 # OpenSSL动态库
        crypto              # OpenSSL动态库
        pthread             # 线程库
        redis               # Redis动态库
        fastcommon          # fastcommon库
        fdfsclient          # fastdfs客户端库
        /usr/local/lib/bcrypt.a # bcrypt静态库
        /usr/lib/x86_64-linux-gnu/libcurl.so # curl 动态库
)


# ========== 6. 输出构建信息（可选） ==========
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Project source dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Linked libraries: mysqlclient, pistache, ssl, crypto, pthread, redis, fastcommon, fdfsclient, bcrypt.a")