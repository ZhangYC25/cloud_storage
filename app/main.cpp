#include "server.h"


int main(){
	MySQLConnPool::getInstance() -> init();
	FdfsConnPool::getInstance() -> init();
	//Api::getInstance();
	//std::shared_ptr<Api> api = std::make_shared<Api>();
	
	Server& server = Server::getInstance();
	
	server.init();
	server.setApi(Api::getInstance());
	server.setRoutes();
	server.start();
	
	//api.reset();
}
