
#pragma once
#include <iostream>

#include <vector>
#include <queue>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "asyncLogger.h"

class uploadThreadPool{

public:
    static uploadThreadPool* getInstance(int8_t pt_num = 4, int8_t max_size = 10);


    template<typename F>
    void submit(F&& f) {
        if (!_stop){
            {
                std::unique_lock<std::mutex> lock(_mtx);
                if (_tasks_queue.size() >= _max_size) {
                    _cv.wait(lock, [this]{return _stop || _tasks_queue.size() < _max_size; });

                }
                _tasks_queue.emplace(std::forward<F>(f));
            }
            _cv.notify_one();
        }
    }

    ~uploadThreadPool(){
        {
            std::lock_guard<std::mutex> lock(_mtx);
            _stop = true;
        }

        _cv.notify_all();
        
        // 等待所有任务执行完（此时不会再有新任务进来）
        {
            std::unique_lock<std::mutex> lock(_mtx);
            _cv.wait(lock, [this] {return _tasks_queue.empty();});
        }

        for(auto& t : _works_queue){
            if (t.joinable()) {
                t.join();
            }
        }
    }


    uploadThreadPool(const uploadThreadPool&) = delete;
    uploadThreadPool& operator=(const uploadThreadPool&) = delete;
    uploadThreadPool(const uploadThreadPool&&) = delete;
    uploadThreadPool& operator=(const uploadThreadPool&&) = delete;

private:
    explicit uploadThreadPool(int8_t& pt_num, int8_t& max_size):_stop{false}, _max_size(max_size){
            for(int8_t i=0; i < pt_num; i++) {
                _works_queue.emplace_back([this]{
                    std::function<void()> task;
                    while (true) {
                        {
                            std::unique_lock<std::mutex> lock(_mtx);
                            _cv.wait(lock, [this]{return _stop || !_tasks_queue.empty();});
                            if (_stop && _tasks_queue.empty()) {
                                return;
                            }
                            task = std::move(_tasks_queue.front());
                            _tasks_queue.pop();
                        }

                        if (task) {
                            task();
                        }
                    }
                });
            }
        }

    std::vector<std::thread> _works_queue;
    std::queue<std::function<void()>> _tasks_queue;
    std::mutex _mtx;
    std::condition_variable _cv;
    std::atomic<bool> _stop{false};
    uint8_t _max_size;
    static uploadThreadPool* _instance;
};

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