import os
import threading
import queue
import win32evtlog
import winerror
import time
import logging
from handle import (
    Event4625Handler,
    Event18456Handler,
    Event7045Handler,
    Event4688Handler,
    Event5156Handler,
)

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class EventLogAnalyzer:
    def __init__(self, evtx_path, save_log_dir, max_queue_size=1000):
        self.handlers = {}  # {event_id: handler}
        self.queue = queue.Queue(maxsize=max_queue_size)
        self.evtx_path = evtx_path
        self.save_log_dir = save_log_dir
        self.worker_threads = []
        self.feed_threads = []
        self.stop_event = threading.Event()

    def register_handler(self, event_id, handler):
        """注册事件ID对应的处理器"""
        self.handlers[event_id] = handler

    def get_log_info(self):
        """获取日志文件的最早记录号和总记录数"""
        try:
            h = win32evtlog.OpenBackupEventLog(None, self.evtx_path)
            oldest = win32evtlog.GetOldestEventLogRecord(h)
            total = win32evtlog.GetNumberOfEventLogRecords(h)
            win32evtlog.CloseEventLog(h)
            return oldest, total
        except Exception as e:
            logging.error(f"Failed to get log info: {e}")
            raise

    def read_range(self, start, end):
        """读取指定范围内的事件日志，并放入队列"""
        try:
            h = win32evtlog.OpenBackupEventLog(None, self.evtx_path)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            offset = start
            while offset <= end and not self.stop_event.is_set():
                events = win32evtlog.ReadEventLog(h, flags, offset)
                if not events:
                    break
                for evt in events:
                    rec_num = evt.RecordNumber
                    if rec_num > end:
                        win32evtlog.CloseEventLog(h)
                        return
                    event_id = winerror.HRESULT_CODE(evt.EventID)
                    if event_id in self.handlers:
                        # 队列满时阻塞，防止内存暴涨
                        self.queue.put({'event_id': event_id, 'event': evt})
                offset = events[-1].RecordNumber + 1 if events else offset + 1
            win32evtlog.CloseEventLog(h)
        except Exception as e:
            logging.error(f"Failed to read range {start}-{end}: {e}")

    def feed_log_file_multithread(self, num_producers=4):
        """启动多个线程读取日志文件"""
        try:
            first, total = self.get_log_info()
        except Exception:
            return

        last = first + total - 1
        step = total // num_producers if num_producers > 0 else total

        logging.info(f"First record: {first}, Last record: {last}, Total: {total}")

        for i in range(num_producers):
            start = first + i * step
            end = last if i == num_producers - 1 else start + step - 1
            t = threading.Thread(target=self.read_range, args=(start, end), name=f"Producer-{i+1}")
            t.daemon = True
            self.feed_threads.append(t)
            t.start()
            logging.info(f"Producer-{i + 1} reading records {start} to {end}")

    def worker(self):
        """消费者线程，从队列中取事件并调用对应处理器"""
        while not self.stop_event.is_set():
            try:
                item = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            if item is None:
                self.queue.task_done()
                break

            try:
                event_id = item.get('event_id')
                event = item.get('event')
                handler = self.handlers.get(event_id)
                if handler:
                    handler.handle(event)
            except Exception as e:
                logging.error(f"Worker error processing event {event_id}: {e}")
            finally:
                self.queue.task_done()

    def worker_log_file_multithread(self, num_workers=2):
        """启动多个消费者线程"""
        for i in range(num_workers):
            t = threading.Thread(target=self.worker, name=f"Worker-{i+1}")
            t.daemon = True
            self.worker_threads.append(t)
            t.start()

    def stop_all(self):
        """停止所有线程"""
        self.stop_event.set()
        # 向队列放入None，通知worker退出
        for _ in self.worker_threads:
            self.queue.put(None)

        for t in self.feed_threads:
            t.join()
        for t in self.worker_threads:
            t.join()

    def run(self, num_producers=4, num_workers=2):
        """启动日志分析流程"""
        self.feed_log_file_multithread(num_producers=num_producers)
        self.worker_log_file_multithread(num_workers=num_workers)

        # 等待所有生产者线程结束
        for t in self.feed_threads:
            t.join()

        # 等待队列处理完成
        self.queue.join()

        self.stop_all()

        self.save_all_results(self.save_log_dir)

    def save_all_results(self, output_dir):
        """保存所有处理器的分析结果"""
        os.makedirs(output_dir, exist_ok=True)
        for handler in self.handlers.values():
            try:
                handler.save_analyze_result(output_dir)
            except Exception as e:
                logging.error(f"Error saving results for handler {handler}: {e}")

if __name__ == "__main__":
    start_time = time.time()

    root_dir = r"E:\xxxxx\Security.evtx"
    save_log_dir = r"E:\xxxxx\save_analyze_result"

    analyzer = EventLogAnalyzer(root_dir, save_log_dir)

    analyzer.register_handler(4625, Event4625Handler())

    try:
        analyzer.run(num_producers=4, num_workers=4)
    except KeyboardInterrupt:
        logging.info("Interrupted by user, stopping...")
        analyzer.stop_all()

    elapsed = time.time() - start_time
    logging.info(f"Elapsed time: {elapsed:.2f} seconds")
