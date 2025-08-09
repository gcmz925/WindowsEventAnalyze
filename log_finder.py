import os
import logging
from event_log_analyzer import EventLogAnalyzer
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

def find_and_analyze_evtx_logs(root_log_dir, analysis_root_dir, target_event_ids=None, need_result=None):
    """
    递归查找evtx日志文件，分析并保存结果。

    :param root_log_dir: 日志根目录，递归查找evtx文件
    :param analysis_root_dir: 分析结果根目录，保存结果时保持相对路径结构
    :param target_event_ids: 需要注册并分析的事件ID列表，默认只分析4625
    :param need_result: 只分析文件名在此列表中的日志文件，默认None表示分析所有evtx文件
    """
    if target_event_ids is None:
        target_event_ids = [4625]

    if need_result is not None:
        # 统一小写，方便匹配
        need_result = set(name.lower() for name in need_result)

    for dirpath, _, filenames in os.walk(root_log_dir):
        for filename in filenames:
            if filename.lower().endswith('.evtx'):
                if need_result is not None and filename.lower() not in need_result:
                    # 跳过不在need_result列表中的文件
                    continue

                full_log_path = os.path.join(dirpath, filename)
                # 计算日志文件相对于root_log_dir的相对路径
                rel_path = os.path.relpath(full_log_path, root_log_dir)
                # 去掉文件名，保留目录结构
                rel_dir = os.path.dirname(rel_path)

                # 构造分析结果保存目录，保持原目录结构
                save_dir = os.path.join(analysis_root_dir, rel_dir)
                os.makedirs(save_dir, exist_ok=True)

                logging.info(f"Found log: {full_log_path}")
                logging.info(f"Saving analysis to: {save_dir}")

                # 创建分析器实例
                analyzer = EventLogAnalyzer(full_log_path, save_dir)

                # 注册需要的事件处理器
                for event_id in target_event_ids:
                    if event_id == 4625:
                        analyzer.register_handler(4625, Event4625Handler())
                    elif event_id == 18456:
                        analyzer.register_handler(18456, Event18456Handler())
                    elif event_id == 7045:
                        analyzer.register_handler(7045, Event7045Handler())
                    elif event_id == 4688:
                        analyzer.register_handler(4688, Event4688Handler())
                    elif event_id == 5156:
                        analyzer.register_handler(5156, Event5156Handler())
                    else:
                        logging.warning(f"No handler registered for event ID {event_id}")

                # 运行分析
                analyzer.run(num_producers=4, num_workers=4)

if __name__ == "__main__":
    root_log_dir = r"E:\Develop\EveryDay\20250730\环境收集"
    analysis_root_dir = r"E:\Develop\EveryDay\20250730\分析结果目录"

    # 只分析这些文件名的日志，None表示分析所有evtx文件
    need_result = ["系统.evtx", "安全.evtx", "应用程序.evtx"]

    find_and_analyze_evtx_logs(
        root_log_dir,
        analysis_root_dir,
        target_event_ids=[4625, 18456, 7045, 4688, 5156],
        need_result=need_result
    )
