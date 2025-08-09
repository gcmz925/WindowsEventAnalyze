"""
event_7045_handler.py

Event7045Handler 类用于处理 Windows 安全事件 ID 7045（服务安装事件）。

功能说明：
- 解析事件中的服务安装相关信息，包括服务名称、映像路径、服务类型、启动类型和事件时间。
- 将解析结果以结构化字典形式存储，支持批量处理多个事件。
- 分析结果保存为文本文件（7045_analyze.txt），格式化输出各字段，便于查看和审计。
- 具备异常捕获和日志记录，保证程序稳定运行。

使用示例：
    handler = Event7045Handler()
    handler.handle(event)  # 处理单个事件
    handler.save_analyze_result(output_dir)  # 保存分析结果

作者：
日期：
"""


import os
import logging
import traceback
from .base import EventHandler

class Event7045Handler(EventHandler):
    def init_result(self):
        self.results = []

    def handle(self, event):
        try:
            message = list(event.StringInserts or [])
            svr_info = {
                'StartTime': event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
                'ServiceName': message[0] if len(message) > 0 else '',
                'ImagePath': message[1] if len(message) > 1 else '',
                'ServiceType': message[2] if len(message) > 2 else '',
                'StartType': message[3] if len(message) > 3 else '',
            }
            self.results.append(svr_info)
        except Exception as e:
            logging.error(f"Event7045Handler.handle error: {e}")
            logging.error(traceback.format_exc())

    def save_analyze_result(self, output_dir):
        if not self.results:
            return

        try:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, "7045_analyze.txt")

            with open(file_path, 'w', encoding='utf-8') as f:
                for event in self.results:
                    event_str = (
                        f"StartTime: {event['StartTime']:<25}, "
                        f"StartType: {event['StartType']:<15}, "
                        f"ServiceType: {event['ServiceType']:<25}, "
                        f"ServiceName: {event['ServiceName']:<60}, "
                        f"ImagePath: {event['ImagePath']:<400}"
                    )
                    f.write(event_str + '\n')

            logging.info(f"Event7045 analysis results saved to: {file_path}")

        except Exception as e:
            logging.error(f"Event7045Handler.save_analyze_result error: {e}")
            logging.error(traceback.format_exc())
