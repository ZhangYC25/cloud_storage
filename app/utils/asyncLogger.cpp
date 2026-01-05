
#include "asyncLogger.h"

AsyncLogger* AsyncLogger::_instance = nullptr;

AsyncLogger* AsyncLogger::getInstance(){
    // static AsyncLogger inst;
    // return inst;

    if (_instance == nullptr) {
        static std::mutex instanceMutex;
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (_instance == nullptr) {
            _instance = new AsyncLogger();
        }
    }
    return _instance;
}

void AsyncLogger::start(const std::string& path){
    if (running.load(std::memory_order_acquire)) return;
    _file.open(path, std::ios::app);
    if (!_file.is_open()) {
        std::cerr << "无法打开日志文件: " << path << std::endl;
        return;
    }
    running.store(true, std::memory_order_release);
    worker = std::thread(&AsyncLogger::run, this);
}

void AsyncLogger::run(){
    
    while (running.load(std::memory_order_acquire)) {
        std::queue<std::string> tmp_queue;
        {
            std::unique_lock<std::mutex> lock(_mtx);
            // 等待直到：1. 停止运行 2. 写队列有东西
            _cv.wait_for(lock, std::chrono::seconds(1), [this] {
                return !running.load(std::memory_order_acquire) || !_write_queue.empty();
            });

            if (_write_queue.empty() && !running.load(std::memory_order_acquire)) {
                break; 
            }

            // 交换到临时队列，这样写磁盘时不需要占用主互斥锁
            std::swap(_write_queue, tmp_queue);
        }

        // 在锁外处理 IO，不阻塞前台业务
        flush_queue(tmp_queue);
        if (_file.is_open()) {
            _file.flush();
        }
    }
}

void AsyncLogger::stop(){
    if (!running.load(std::memory_order_acquire)) return;

        running.store(false, std::memory_order_release);
        _cv.notify_one();  // 唤醒后台线程

        if (worker.joinable()) {
            worker.join();
        }

        // 最后把当前写队列也处理掉
        flush_queue(_write_queue);
        _file.flush();
        _file.close();
}

void AsyncLogger::flush_queue(std::queue<std::string>& q){
    while (!q.empty()) {
        if (_file.is_open()) {
            _file << q.front();
        }
        q.pop();
    }
}

std::string AsyncLogger::get_current_time(){
    auto now = std::chrono::system_clock::now();
    auto tt = std::chrono::system_clock::to_time_t(now);
    //auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        //now.time_since_epoch()) % 1000;
    
    // 线程安全
    std::tm tm_local{};
    localtime_r(&tt, &tm_local);
    std::ostringstream oss;
    oss << std::put_time(&tm_local, "%Y-%m-%d %H:%M:%S");
        //<< '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}