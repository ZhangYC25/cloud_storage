
#include "asyncLogger.h"

#include <cstdio>

AsyncLogger* AsyncLogger::_instance = nullptr;

namespace {
constexpr int kLogRetentionDays = 30;
constexpr auto kPruneInterval = std::chrono::hours(24);
}  // namespace

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
    _log_path = path;
    pruneOldLogs(kLogRetentionDays);
    _file.open(path, std::ios::app);
    if (!_file.is_open()) {
        std::cerr << "无法打开日志文件: " << path << std::endl;
        return;
    }
    _last_prune_time = std::chrono::steady_clock::now();
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

        const auto now = std::chrono::steady_clock::now();
        if (!_log_path.empty() &&
            now - _last_prune_time >= kPruneInterval) {
            std::queue<std::string> pending;
            {
                std::lock_guard<std::mutex> lock(_mtx);
                std::swap(_write_queue, pending);
            }
            flush_queue(pending);
            if (_file.is_open()) {
                _file.close();
            }
            pruneOldLogs(kLogRetentionDays);
            _file.open(_log_path, std::ios::app);
            _last_prune_time = now;
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
    
    std::tm tm_local{};
    localtime_r(&tt, &tm_local);
    std::ostringstream oss;
    oss << std::put_time(&tm_local, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

bool AsyncLogger::parseLogTimestamp(const std::string& line, std::tm& out_tm) {
    if (line.size() < 19) {
        return false;
    }

    std::istringstream iss(line.substr(0, 19));
    iss >> std::get_time(&out_tm, "%Y-%m-%d %H:%M:%S");
    return !iss.fail();
}

void AsyncLogger::pruneOldLogs(int retention_days) {
    if (_log_path.empty()) {
        return;
    }

    std::ifstream in(_log_path);
    if (!in.is_open()) {
        return;
    }

    const auto cutoff_time = std::chrono::system_clock::now() -
                             std::chrono::hours(24 * retention_days);
    const std::time_t cutoff = std::chrono::system_clock::to_time_t(cutoff_time);

    const std::string temp_path = _log_path + ".tmp";
    std::ofstream out(temp_path, std::ios::trunc);
    if (!out.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }

        std::tm line_tm{};
        if (!parseLogTimestamp(line, line_tm)) {
            out << line << '\n';
            continue;
        }

        if (std::mktime(&line_tm) >= cutoff) {
            out << line << '\n';
        }
    }

    in.close();
    out.close();

    if (std::rename(temp_path.c_str(), _log_path.c_str()) != 0) {
        std::remove(temp_path.c_str());
    }
}