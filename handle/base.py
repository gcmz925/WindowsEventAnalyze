import logging
import traceback

class EventHandler:
    def __init__(self):
        self.results = None
        self.init_result()

    def init_result(self):
        """
        初始化结果数据结构，子类必须实现
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def handle(self, event):
        """
        处理单个事件，子类必须实现
        :param event: 事件对象
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def save_analyze_result(self, output_dir):
        """
        保存分析结果，子类必须实现
        :param output_dir: 结果保存目录
        """
        raise NotImplementedError("Subclasses must implement this method.")
