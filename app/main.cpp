#include "server/server.h"


/*
git reset --soft HEAD~1

*/
int main(){
	MySQLConnPool::getInstance() -> init();
	FdfsConnPool::getInstance() -> init();
	RedisConnPool::getInstance() -> init();
	//运行在 build 目录下，所以这里的相对路径是 ../log/error.log
	AsyncLogger::getInstance() -> start("../log/error.log");
	//Api::getInstance();
	//std::shared_ptr<Api> api = std::make_shared<Api>();
	
	Server& server = Server::getInstance();
	
	server.init();
	server.setApi(Api::getInstance());
	server.setRoutes();
	server.start();
	
	//api.reset();
}
