# handlers.py
import os
import win32evtlog
import os
import winerror
from collections import defaultdict
import traceback

class EventHandler:
    def __init__(self):
        self.results = None
        self.init_result()

    def init_result(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def handle(self, event_ims):
        raise NotImplementedError("Subclasses must implement this method.")

    def save_analyze_result(self, output_dir):
        """
            保存当前 handler 的分析结果到文本
            保留结果时要先进行排序，多线程读取添加不能保证顺序
        """
        raise NotImplementedError("Subclasses must implement this method.")

class Event4625Handler(EventHandler):
    def init_result(self):
        self.results = {
            "start_time": None,
            "end_time": None,
            "total_events": 0,
            "user_login": defaultdict(int),
            "ip_login": defaultdict(int),
        }

    def handle(self, event_ims):
        try:
            self.results['total_events'] += 1
            message = list(event_ims.StringInserts) if event_ims.StringInserts else []

            if len(message) < 19:
                return

            # 更新时间
            event_time = event_ims.TimeGenerated
            if self.results['start_time'] is None or event_time < self.results['start_time']:
                self.results['start_time'] = event_time
            if self.results['end_time'] is None or event_time > self.results['end_time']:
                self.results['end_time'] = event_time

            # 统计用户登录次数
            user = message[5]
            self.results['user_login'][user] += 1

            # 统计IP登录次数
            ip = message[19] if message[19] != '-' else '未知'
            self.results['ip_login'][ip] += 1
        except Exception as e:
            print("Event4625Handler.handle 异常：{}".format(e))
            traceback.print_exc()
        return None

    def save_analyze_result(self, output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            file_path = os.path.join(output_dir, "4625.txt")

            sorted_user_logins = sorted(self.results['user_login'].items(), key=lambda x: x[1], reverse=True)
            sorted_ip_logins = sorted(self.results['ip_login'].items(), key=lambda x: x[1], reverse=True)

            with open(file_path, 'w', encoding='utf-8') as file:
                # 写入统计结果
                file.write("最早开始的时间: {}\n".format(self.results['start_time']))
                file.write("最后结束的时间: {}\n".format(self.results['end_time']))
                file.write("登录事件总数: {}\n".format(self.results['total_events']))
                file.write("\nIP登录统计（按登录次数由高到低排序）:\n")

                for ip, count in sorted_ip_logins:
                    file.write("IP: {}, 登录次数: {}\n".format(ip, count))

                file.write("\n用户登录统计（按登录次数由高到低排序）:\n")
                for user, count in sorted_user_logins:
                    file.write("用户: {}, 登录次数: {}\n".format(user, count))

                print("结果已保存到文件: {}".format(file_path))
        except Exception as e:
            print("Event4625Handler.save_analyze_result 异常：{}".format(e))
            traceback.print_exc()
        return None