"""
event_4688_handler.py

Event4688Handler 类用于处理 Windows 安全事件 ID 4688（新进程创建事件）。

功能说明：
- 统计所有出现过的进程名称，去重保存。
- 支持自定义关注的目标进程列表（默认关注 'w3wp.exe' 和 'ssms.exe'），
  对这些进程收集详细的进程创建信息，包括时间、进程名、PID、父进程名和父PID。
- 结果分两部分保存：
  1. 所有进程名称列表（4688_process_names.txt）
  2. 关注进程的详细事件信息（4688_detailed.txt）
- 支持模糊匹配，忽略大小写。
- 具备异常捕获和日志记录，保证稳定运行。

使用示例：
    handler = Event4688Handler(target_processes=['w3wp.exe', 'ssms.exe', 'notepad.exe'])
    handler.handle(event)  # 处理单个事件
    handler.save_analyze_result(output_dir)  # 保存分析结果

作者：
日期：
"""

import os
import logging
import traceback
from .base import EventHandler

class Event4688Handler(EventHandler):
    def __init__(self, target_processes=None):
        """
        :param target_processes: 关注的进程名列表，支持模糊匹配，默认关注 ['w3wp.exe', 'ssms.exe']
        """
        self.target_processes = target_processes or ['w3wp.exe', 'ssms.exe']
        super().__init__()

    def init_result(self):
        self.results = set()
        self.results_detailed = []

    def handle(self, event):
        try:
            message = list(event.StringInserts or [])
            if len(message) < 14:
                return

            process_name = message[5]
            process_pid = message[4]
            parent_process = message[13]
            parent_pid = message[7]
            time_generated = event.TimeGenerated

            # 记录所有进程名
            self.results.add(process_name)

            # 只收集关注进程的详细信息，支持模糊匹配
            if any(target.lower() in process_name.lower() for target in self.target_processes):
                line_data = {
                    "TimeGenerated": time_generated,
                    "ProcessName": process_name,
                    "PID": process_pid,
                    "ParentProcess": parent_process,
                    "ParentPID": parent_pid
                }
                self.results_detailed.append(line_data)

        except Exception as e:
            logging.error(f"Event4688Handler.handle error: {e}")
            logging.error(traceback.format_exc())

    def save_analyze_result(self, output_dir):
        try:
            if not self.results and not self.results_detailed:
                logging.info("No data to save for Event4688.")
                return

            os.makedirs(output_dir, exist_ok=True)

            # 保存所有进程名
            if self.results:
                file_path_simple = os.path.join(output_dir, "4688_process_names.txt")
                with open(file_path_simple, 'w', encoding='utf-8') as f:
                    f.write("\n")
                    f.write("-" * 50)
                    f.write("\n")
                    for name in sorted(self.results):
                        f.write(f"{name}\n")
                logging.info(f"Event4688 process names saved to: {file_path_simple}")

            # 保存详细信息，按时间排序
            if self.results_detailed:
                file_path_detailed = os.path.join(output_dir, "4688_detailed.txt")
                sorted_details = sorted(self.results_detailed, key=lambda x: x["TimeGenerated"])
                with open(file_path_detailed, 'w', encoding='utf-8') as f:
                    f.write("\n")
                    f.write("-" * 50)
                    f.write("\n")
                    for item in sorted_details:
                        line = (f"TimeGenerated: {item['TimeGenerated']}, "
                                f"ProcessName: {item['ProcessName']}, PID: {item['PID']}, "
                                f"ParentProcess: {item['ParentProcess']}, ParentPID: {item['ParentPID']}")
                        f.write(line + "\n")
                logging.info(f"Event4688 detailed info saved to: {file_path_detailed}")

        except Exception as e:
            logging.error(f"Event4688Handler.save_analyze_result error: {e}")
            logging.error(traceback.format_exc())



