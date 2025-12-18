#pragma once

#include <sstream>
#include <fstream>
#include <iostream>
#include <queue>
#include <string>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <chrono>
#include <iomanip>


#define MY_LOG_INFO(...) AsyncLogger::getInstance() -> log("INFO", ##__VA_ARGS__);
#define MY_LOG_WARN(...) AsyncLogger::getInstance() -> log("WARN", ##__VA_ARGS__);
#define MY_LOG_ERROR(...) AsyncLogger::getInstance() -> log("ERROR", ##__VA_ARGS__);
#define MY_LOG_DEBUG(...) AsyncLogger::getInstance() -> log("DEBUG", ##__VA_ARGS__);


class AsyncLogger{
public:
    static AsyncLogger* getInstance();

    void start(const std::string& log_file);
    void stop();

    // 可变参数日志函数
    template<typename... Args>
    void log(const std::string& level, const Args&... args) {
        if (!running.load(std::memory_order_acquire)) return;

        std::ostringstream oss;
        oss << get_current_time() << " [" << level << "] ";
        ((oss << args << " "), ...);  // C++17 fold expression
        oss << "\n";

        std::string msg = oss.str();

        {
            std::lock_guard<std::mutex> lock(_mtx);
            _write_queue.push(std::move(msg));

            // 可选：队列太长时立即交换（防止内存爆炸）
            if (_write_queue.size() > 10000) {
                //swap_queues();
                {
                    std::lock_guard<std::mutex> lock(_mtx);
                    std::swap(_write_queue, _read_queue);
                }
                _cv.notify_one();
            }
        }
    }


private:
    AsyncLogger() = default;
    ~AsyncLogger() { stop(); }  // 析构时自动停止
    std::string get_current_time();
    void flush_queue(std::queue<std::string>& q);

    void run();
private:
    std::ofstream _file;
    std::queue<std::string> _write_queue;
    std::queue<std::string> _read_queue;

    std::mutex _mtx;
    std::condition_variable _cv;
    std::thread worker;
    std::atomic<bool> running{false};

    static AsyncLogger* _instance;
};