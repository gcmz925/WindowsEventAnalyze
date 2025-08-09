"""
event_18456_handler.py

Event18456Handler 类用于处理 Windows 安全事件 ID 18456（SQL Server 登录失败事件）。

功能说明：
- 统计事件的起止时间、总事件数。
- 统计登录失败的用户和来源 IP 的次数。
- 支持将统计结果保存为文本文件（18456_analyze.txt），包括登录失败用户和 IP 的排序统计。
- 具备异常捕获和日志记录，保证程序稳定运行。

使用示例：
    handler = Event18456Handler()
    handler.handle(event)  # 处理单个事件
    handler.save_analyze_result(output_dir)  # 保存分析结果

作者：
日期：
"""


import os
import logging
import traceback
from collections import defaultdict
from .base import EventHandler

class Event18456Handler(EventHandler):
    def init_result(self):
        self.results = {
            "start_time": None,
            "end_time": None,
            "total_events": 0,
            "user_login_counts": defaultdict(int),
            "ip_login_counts": defaultdict(int),
        }

    def handle(self, event):
        try:
            self.results['total_events'] += 1
            message = list(event.StringInserts) if event.StringInserts else []

            if len(message) < 3:
                return

            event_time = event.TimeGenerated
            if self.results['start_time'] is None or event_time < self.results['start_time']:
                self.results['start_time'] = event_time
            if self.results['end_time'] is None or event_time > self.results['end_time']:
                self.results['end_time'] = event_time

            user = message[0]
            self.results['user_login_counts'][user] += 1

            ip = message[2]
            if ip == '-' or not ip:
                ip = 'UNKNOWN'
            self.results['ip_login_counts'][ip] += 1

        except Exception as e:
            logging.error(f"Event18456Handler.handle error: {e}")
            logging.error(traceback.format_exc())

    def save_analyze_result(self, output_dir):
        if self.results['total_events'] == 0:
            return

        try:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, "18456_analyze.txt")

            sorted_user_logins = sorted(self.results['user_login_counts'].items(), key=lambda x: x[1], reverse=True)
            sorted_ip_logins = sorted(self.results['ip_login_counts'].items(), key=lambda x: x[1], reverse=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"Start Time: {self.results['start_time']}\n")
                f.write(f"End Time: {self.results['end_time']}\n")
                f.write(f"Total Events: {self.results['total_events']}\n\n")

                f.write("IP Login Counts:\n")
                for ip, count in sorted_ip_logins:
                    f.write(f"IP: {ip}, Count: {count}\n")

                f.write("\nUser Login Counts:\n")
                for user, count in sorted_user_logins:
                    f.write(f"User: {user}, Count: {count}\n")

            logging.info(f"Event18456 analysis results saved to: {file_path}")

        except Exception as e:
            logging.error(f"Event18456Handler.save_analyze_result error: {e}")
            logging.error(traceback.format_exc())
