# analyzer.py

import os
import threading
import queue
import win32evtlog
import winerror
import time
from collections import defaultdict
from handlers import Event4625Handler

class EventLogAnalyzer:
    def __init__(self, evtx_path, save_log_dir):
        self.handlers = {}                          # 存储 {event_id: handler 实例}
        self.queue = queue.Queue()                  # 用于多线程处理的任务队列
        self.event_log_handle = None                # 事件日志句柄
        self.stop = False
        self.worker_threads = []
        self.feed_threads = []
        self.evtx_path = evtx_path
        self.save_log_dir = save_log_dir

    def stop_all(self):
        # 给每个线程发一个 None 哨兵
        for _ in self.worker_threads:
            self.queue.put(None)

        for t in self.worker_threads:
            t.join()

    def register_handler(self, event_id, handler):
        """注册某个事件 ID 对应的处理器"""
        self.handlers[event_id] = handler

    def get_log_info(self):
        """获取最早记录号和总记录数"""
        h = win32evtlog.OpenBackupEventLog(None, self.evtx_path)
        oldest = win32evtlog.GetOldestEventLogRecord(h)
        total = win32evtlog.GetNumberOfEventLogRecords(h)
        win32evtlog.CloseEventLog(h)
        return oldest, total

    def read_range(self, start, end):
        """读取一个区间的日志并放入队列"""
        try:
            h = win32evtlog.OpenBackupEventLog(None, self.evtx_path)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            offset = start
            while offset <= end:
                events = win32evtlog.ReadEventLog(h, flags, offset)
                if not events:
                    break
                for evt in events:
                    rec_num = evt.RecordNumber
                    if rec_num > end:
                        return
                    event_id = winerror.HRESULT_CODE(evt.EventID)
                    if event_id in self.handlers:
                        self.queue.put({'event_id': event_id, 'event': evt})
                offset = events[-1].RecordNumber + 1
            win32evtlog.CloseEventLog(h)
        except Exception as e:
            print(f"[ERROR] Failed to read range {start}-{end}: {e}")

    def feed_log_file_multithread(self, num_producers=4):
        """多线程读取日志并放入队列"""
        first, total = self.get_log_info()
        last = first + total - 1
        step = total // num_producers

        print(f"[INFO] First record: {first}, Last record: {last}, Total: {total}")

        for i in range(num_producers):
            start = first + i * step
            end = last if i == num_producers - 1 else start + step - 1
            t = threading.Thread(target=self.read_range, args=(start, end))
            self.feed_threads.append(t)
            t.start()
            print(f"[INFO] Producer-{i + 1} will read {start} → {end}")

    def worker_log_file_multithread(self, num_producers=2):
        for _ in range(num_producers):
            t = threading.Thread(target=self.worker)
            t.start()
            self.worker_threads.append(t)

    def worker(self):
        while True:
            # print('消费 ： {}'.format(self.queue.qsize()))
            item = self.queue.get()
            if item is None:  # 哨兵值，通知线程退出
                print('worker 收到退出信号')
                self.queue.task_done()
                break

            try:
                event_id = item.get('event_id')
                event = item.get('event')
                handler = self.handlers.get(event_id, None)
                if handler:
                    handler.handle(event)
            except Exception as e:
                print('worker error: {}'.format(e))
            finally:
                self.queue.task_done()

    def run(self, num_threads=4):
        """启动多线程处理日志"""

        self.feed_log_file_multithread()

        self.worker_log_file_multithread()

        # 读取完毕后发送空包
        for t in self.feed_threads:
            t.join()

        # print(f"[INFO] Finished reading logs. Total events queued: {self.queue.qsize()}")

        self.stop_all()

        self.save_all_results(save_log_dir)

    def save_all_results(self, output_dir):
        """调用每个处理器保存结果"""
        os.makedirs(output_dir, exist_ok=True)
        for handler in self.handlers.values():
            handler.save_analyze_result(output_dir)

if __name__ == "__main__":
    start_time = time.time()

    # root_dir = r"E:\Develop\EveryDay\20250730\安全.evtx"
    # save_log_dir = r"E:\Develop\EveryDay\20250730\save_analyze_result2"

    root_dir = r"E:\Develop\EveryDay\20250730\分析\192.168.0.5\Logs\Security.evtx"
    save_log_dir = r"E:\Develop\EveryDay\20250423\0408\10.70.11.109\Logs\save_analyze_result2"

    analyzer = EventLogAnalyzer(root_dir, save_log_dir)

    analyzer.register_handler(4625, Event4625Handler())

    analyzer.run()


    end_time = time.time()
    elapsed = end_time - start_time
    print("日志分析总耗时：{:.2f} 秒".format(elapsed))