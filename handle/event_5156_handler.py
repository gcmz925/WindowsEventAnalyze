"""
event_5156_handler.py

Event5156Handler 类用于处理 Windows 安全事件 ID 5156（Windows Filtering Platform 事件）。

功能说明：
- 按应用程序（APP）分类，分别统计入站（Inbound）和出站（Outbound）网络连接事件。
- 事件数据以结构化字典形式存储，包含时间、进程ID、源IP及端口、目标IP及端口。
- 支持对入站和出站连接分别按时间排序，方便后续分析和审计。
- 结果保存为文本文件（5156_analyze.txt），格式清晰，便于阅读。
- 具备异常捕获和日志记录，保证程序稳定运行。

使用示例：
    handler = Event5156Handler()
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

# 下面是类定义和代码...


import os
import logging
import traceback
from collections import defaultdict
from .base import EventHandler

class Event5156Handler(EventHandler):
    def init_result(self):
        # 结构：{app_name: {'in': list(), 'out': list()}}
        # 每个列表存储结构化字典，方便排序和格式化输出
        self.results = defaultdict(lambda: {'in': [], 'out': []})

    def handle(self, event):
        try:
            message = list(event.StringInserts) if event.StringInserts else []
            if len(message) < 7:
                return

            pid = message[0]
            app = message[1]
            direction = message[2]
            src_ip = message[3]
            src_port = message[4]
            dst_ip = message[5]
            dst_port = message[6]

            info = {
                'time': event.TimeGenerated,
                'pid': pid,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port
            }

            if direction == '%%14592':
                self.results[app]['in'].append(info)
            elif direction == '%%14593':
                self.results[app]['out'].append(info)

        except Exception as e:
            logging.error(f"Event5156Handler.handle error: {e}")
            logging.error(traceback.format_exc())

    def save_analyze_result(self, output_dir):
        if not self.results:
            logging.info("No data to save for Event5156.")
            return

        try:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, "5156_analyze.txt")

            with open(file_path, 'w', encoding='utf-8') as f:
                for app, connections in self.results.items():
                    if not connections['in'] and not connections['out']:
                        continue  # 跳过无数据的app

                    f.write("\n")
                    f.write("-" * 50)
                    f.write("\n")
                    f.write(f"APP: {app}\n")

                    # 按时间排序入站连接
                    f.write("Inbound Connections:\n")
                    for conn in sorted(connections['in'], key=lambda x: x['time']):
                        f.write(
                            f"  time: {conn['time']}, pid: {conn['pid']}, "
                            f"src_ip: {conn['src_ip']}:{conn['src_port']} -> "
                            f"dst_ip: {conn['dst_ip']}:{conn['dst_port']}\n"
                        )

                    # 按时间排序出站连接
                    f.write("Outbound Connections:\n")
                    for conn in sorted(connections['out'], key=lambda x: x['time']):
                        f.write(
                            f"  time: {conn['time']}, pid: {conn['pid']}, "
                            f"src_ip: {conn['src_ip']}:{conn['src_port']} -> "
                            f"dst_ip: {conn['dst_ip']}:{conn['dst_port']}\n"
                        )

            logging.info(f"Event5156 analysis results saved to: {file_path}")

        except Exception as e:
            logging.error(f"Event5156Handler.save_analyze_result error: {e}")
            logging.error(traceback.format_exc())
