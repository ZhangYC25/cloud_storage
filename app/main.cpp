#include "server.h"


int main(){
	MySQLConnPool::getInstance() -> init();
	FdfsConnPool::getInstance() -> init();

	Api* api = new Api();
	
	Server& server = Server::getInstance();
	server.init();
	server.setApi(api);
	server.setRoutes();
	server.start();
}
