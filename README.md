# cloud_storage
一个轻量级的文件云存储服务

C++/Nginx/Fastdfs/Pistache

## 当前功能
- 上传自动计算文件MD5，MySQL中储存MD5值，文件存储在Fastdfs中
- 基于MD5 与 Redis去重，不会重复上传文件
- 通过 URL 直接访问文件

## 如何运行
### 环境构建
- 本项目在 Ubuntu22.04 上构建，并且 lib 文件夹中包含了项目需要的所有工具
- 但是实际上你只需要用到其中的fastdfs/fastdfs-nginx-module/libfastcommon/nginx
- 首先安装一些必要的依赖：
```
apt update
apt install -y build-essential libpcre3 libpcre3-dev zlib1g-dev libssl-dev
```
这些依赖在nginx构建中会用到，具体作用可以自己去查询，这里直接apt install就好<br>

**fastdfs**
1. 先安装fastdfs
  ```
  cd fastdfs-6.07
  ./make.sh && ./make.sh install
  ```
  - 注意权限问题，最好使用sudo + command，这种方式运行命令
  - 安装结束后需要对fastdfs的配置文件做修改，配置文件一般在 /etc/fdfs 目录下
  - 如果不在，就 find \ -name "fdfs" 找一下
2. 配置文件
  - 进入到 /etc/fdfs 目录下，**把 XXX.conf.sample 文件都备份一下**，防止改错配置文件
    ```
    cp XXX.conf.sample XXX.conf
    ```
  - 后续都在 XXX.conf 文件中改<br>
  创建 三个文件夹，用来存放日志信息：
```
makir -p /var/fdfs/{tracker storage client}
```
2.1 
*tracker.conf*
  - 找到 base_path 改成 **你的机器上存在** 的路径，这个文件用来放 tracker 的日志信息，这里也可以不改
  - 可以是任意路径，只要这个路径存在就行
  - 启动tracker的命令是 fdfs_trackerd + 配置文件 + start，一般fdfs_trackerd在 /usr/bin 目录下<br>
  找不到就 find / -name "fdfs_trackerd"
```
fdfs_trackerd /etc/fdfs/tracker.conf start
```
2.2 
*storage.conf*
  ```
  group_name=group1
  base_path=/var/fdfs/storage
  store_path0=/home/zhangyc/fastdfs-nginx/data/fdfs/storage
  tracker_server=IP:22122
```
  - storage.conf配置文件至少要改两个地方
  - base_path 同样是存在的路径，这里可以不改
  - store_path0 也必须是存在的路径，用来存放 文件数据，这里需要改成 你的 主机上存在的路径。
  - 这里的 IP 是 Tracker 进程所在的 IP，如果tracker/storage在一台主机上，那就是本机IP，但是不能写 127.0.0.1
  - 同时要把 配置文件中 所有涉及到 路径 的配置信息检查一下，因为 yvqing 保留了绝对路径
启动storage
```
fdfs_storaged /etc/fdfs/storage.conf start
```
2.3 
*client.conf*
  ```
  base_path = /var/fdfs/client
  tracker_server = IP:22122
  ```
  - 同样的，这里的IP是运行tarcker进程 的 主机 IP，如果tracker/storage/client都在一台主机上，那这个 IP 就是本机 IP
  - base_path 给client指定一个存放日志的路径，必须是存在的路径

2.4<br>
```
ps aux | grep fastdfs
```
输入命令，能看到tracker和storage进程，就说明启动成功<br>
**Nginx**
1. 首先
   编译 libfastcommon
```
cd libfastcommon-1.0.46
./make.sh && ./make.sh install
```
- 编译出来的动态库可以在 /usr/lib 下找到
<br>
<br>

2 编译Nginx
```
cd /nginx-1.21.2
./configure --prefix=/usr/local/nginx --add-module=../fastdfs-nginx-module-1.22/src --with-http_ssl_module --with-stream
make && make install
```
  - 注意 这一步会报一个小错误，是关于 错误检查 的，忽略就好。
  - Nginx 的配置文件/可执行文件都会安装在 --perfix 指定的目录下<br>
  
2.1 nginx配置文件
  - 只需要改 nginx.conf,把 79 行的：<br>
  ```
  root /home/zhangyc/fastdfs-nginx/data/fdfs/storage/data;
  ```
  文件存储路径，改成 你 storage 中设置的路径，这里是我的路径<br>
  
2.2 启动 nginx
  ```
  /usr/local/nginx/sbin/nginx -t
  /usr/local/nginx/sbin/nginx
  ```

2.3
```
    ps aux | grep nginx  
```
输入命令可以看到 master/work 进程就说明nginx启动成功
这样 Nginx + Fastdfs 环境就搭好了<br>
总体上需要修改的就是：路径 和 IP

### MySQL / Redis
为了方便，这里都是docker启动
在lib/database分支下有对应的 docker-compose.yaml文件
去对应文件夹执行
```
docker-compose -d up
```
也可以修改自行的 账户 密码
### 代码编译
```
cd app
rm -rf build
mkdir build && cd build
cmake ..
make
```
得到 cloud_storage_server
```
./cloud_storage_server
```

##访问
直接输入运行Nginx的主机IP就可以访问，如果只有一台主机，那理论上来说tracker/storage/nginx的IP是一样的<br>

你也可以输入我的IP
```146.56.194.96```
