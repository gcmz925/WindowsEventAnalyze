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
    def __init__(self):
        self.handlers = {}                          # 存储 {event_id: handler 实例}
        self.queue = queue.Queue()                  # 用于多线程处理的任务队列
        self.results = defaultdict(list)            # 存储每个事件 ID 的处理结果
        self.event_log_handle = None                # 事件日志句柄

    def register_handler(self, event_id, handler):
        """注册某个事件 ID 对应的处理器"""
        self.handlers[event_id] = handler

    def open_log(self, log_type='Security'):
        """打开指定类型的事件日志"""
        try:
            self.event_log_handle = win32evtlog.OpenBackupEventLog(None, log_type)
        except Exception as e:
            print(f"无法打开事件日志: {e}")
            self.event_log_handle = None

    def feed_log_file(self):
        """读取事件日志并放入队列"""
        if self.event_log_handle is None:
            print("事件日志句柄未打开")
            return

        try:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(self.event_log_handle, flags, 0)

            while events:
                for event in events:
                    event_id = winerror.HRESULT_CODE(event.EventID)
                    if event_id in self.handlers:
                        self.queue.put({
                            'event_id': event_id,
                            'event': event
                        })
                events = win32evtlog.ReadEventLog(self.event_log_handle, flags, 0)

        except Exception as e:
            print("读取事件日志时发生错误: {}".format(e))

    def worker(self):
        while not self.queue.empty():
            try:
                event_ims = self.queue.get()
                event_id = event_ims.get('event_id')
                event = event_ims.get('event')
                handler = self.handlers.get(event_id, None)
                if handler:
                    handler.handle(event)
            except Exception as e:
                print('worker error: {}'.format(e))
            finally:
                self.queue.task_done()

    def run(self, num_threads=4):
        """启动多线程处理日志"""
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return self.results

    def save_all_results(self, output_dir):
        """调用每个处理器保存结果"""
        os.makedirs(output_dir, exist_ok=True)
        for handler in self.handlers.values():
            if hasattr(handler, "save_analyze_result2"):
                handler.save_analyze_result(output_dir)

if __name__ == "__main__":
    start_time = time.time()

    root_dir = r"E:\Develop\EveryDay\20250730\王致和防勒索环境收集\192.168.0.5\安全.evtx"
    save_log_dir = r"E:\Develop\EveryDay\20250730\王致和防勒索环境收集\192.168.0.5\save_analyze_result2"

    analyzer = EventLogAnalyzer()
    analyzer.register_handler(4625, Event4625Handler())

    analyzer.open_log(root_dir)
    analyzer.feed_log_file()
    analyzer.run(num_threads=6)
    analyzer.save_all_results(save_log_dir)

    end_time = time.time()
    elapsed = end_time - start_time
    print("日志分析总耗时：{:.2f} 秒".format(elapsed))