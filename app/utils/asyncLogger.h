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
#include <ctime>


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
        }
        _cv.notify_one(); // 唤醒后台线程开始干活
    }


private:
    AsyncLogger() = default;
    ~AsyncLogger() { stop(); }  // 析构时自动停止
    std::string get_current_time();
    void flush_queue(std::queue<std::string>& q);
    void pruneOldLogs(int retention_days = 30);
    static bool parseLogTimestamp(const std::string& line, std::tm& out_tm);

    void run();
private:
    std::string _log_path;
    std::ofstream _file;
    std::queue<std::string> _write_queue;

    std::mutex _mtx;
    std::condition_variable _cv;
    std::thread worker;
    std::atomic<bool> running{false};
    std::chrono::steady_clock::time_point _last_prune_time{};

    static AsyncLogger* _instance;
};