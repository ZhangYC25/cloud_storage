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
# MySQL头文件路径
# include_directories(/usr/include/mysql)
# Pistache头文件路径（源码编译的头文件通常在build/include或安装到/usr/local/include
include_directories(/usr/local/include)
# bcrypt头文件路径（你的bcrypt目录）
include_directories(/home/zhangyc/cloud_storage/bcrypt)
# nlohmann/json头文件路径（若手动下载到third_party）
# include_directories(/usr/include/nlohmann)

# 添加fastcommon头文件目录
include_directories(/usr/include/fastcommon)
include_directories(/usr/include/fastdfs)


# ========== 2. 库路径配置 ==========
# MySQL库路径
# link_directories(/usr/lib/x86_64-linux-gnu)
# Pistache库路径（你本地编译的路径）
# link_directories(/home/zhangyc/fastdfs-nginx/pistache/build/src)
# OpenSSL库路径
# link_directories(/usr/lib/x86_64-linux-gnu)


# ========== 3. 源文件配置 ==========
set(SOURCES
    main.cpp  # 你的主代码文件
   )


# ========== 4. 生成可执行文件 ==========
add_executable(cloud_storage_server ${SOURCES})


# ========== 5. 链接库 ==========
target_link_libraries(cloud_storage_server
    PRIVATE
        # 动态库（按你的路径）
        mysqlclient         # MySQL动态库
        pistache            # Pistache动态库
        ssl                  # OpenSSL动态库
        crypto               # OpenSSL动态库
        pthread              # 线程库
        redis                # Redis 动态库
        fastcommon           # fastdfs
	fdfsclient
	/home/zhangyc/cloud_storage/bcrypt/bcrypt.a
)


# ========== 6. 输出构建信息（可选） ==========
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Linked libraries: mysqlclient, pistache, ssl, crypto, pthread, bcrypt.a")
