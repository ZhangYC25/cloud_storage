#include "threadPool.h"


uploadThreadPool* uploadThreadPool::_instance = nullptr;

uploadThreadPool* uploadThreadPool::getInstance(int8_t pt_num, int8_t max_size){
    if (_instance == nullptr) {
        static std::mutex instanceMutex;
        {
            std::lock_guard<std::mutex> lock(instanceMutex);
            _instance = new uploadThreadPool(pt_num, max_size);
        }
    }
    return _instance;
}

void uploadThreadPool::destroyInstance() {
    static std::mutex _instanceMtx;
    std::lock_guard<std::mutex> lock(_instanceMtx);
    if (_instance) {
        delete _instance; // 这里会自动调用析构函数
        _instance = nullptr;
    }
}