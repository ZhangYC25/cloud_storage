
#include "server/server.h"

/*
git reset --soft HEAD~1

*/
int main(){
	//运行在 build 目录下，所以这里的相对路径是 ../log/error.log
	AsyncLogger::getInstance() -> start("../log/error.log");
	
	MySQLConnPool::getInstance() -> init();
	FdfsConnPool::getInstance() -> init();
	RedisConnPool::getInstance() -> init();
	
	Server& server = Server::getInstance();
	server.init();
	//server.setApi(Api::getInstance());
	server.setApi();
	server.setRoutes();
	server.start();

	return 0;
}
