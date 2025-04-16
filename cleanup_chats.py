#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
聊天记录清理脚本 - 删除30天前的聊天记录
"""

import sqlite3
from datetime import datetime, timedelta
import logging
import sys
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'cleanup_logs.log'))
    ]
)
logger = logging.getLogger(__name__)

def cleanup_old_chats(days=30, db_path='users.db'):
    """
    清理指定天数前的聊天记录
    
    参数:
        days (int): 要保留的天数，默认为30天
        db_path (str): 数据库文件路径
    """
    try:
        # 计算截止日期
        cutoff_date = datetime.now() - timedelta(days=days)
        cutoff_timestamp = cutoff_date.timestamp()
        
        # 连接数据库
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 获取要删除的聊天ID
        cursor.execute("SELECT id FROM chats WHERE last_activity < ?", (cutoff_timestamp,))
        old_chat_ids = [row[0] for row in cursor.fetchall()]
        
        if not old_chat_ids:
            logger.info(f"没有发现超过{days}天的聊天记录")
            conn.close()
            return
        
        # 记录要删除的聊天数量
        chat_count = len(old_chat_ids)
        logger.info(f"找到{chat_count}个超过{days}天的聊天记录")
        
        # 开始事务
        conn.execute("BEGIN TRANSACTION")
        
        try:
            # 首先删除相关消息（由于外键约束）
            for chat_id in old_chat_ids:
                cursor.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
                msg_count = cursor.rowcount
                logger.debug(f"从聊天ID {chat_id} 中删除了 {msg_count} 条消息")
            
            # 删除聊天记录
            placeholders = ','.join(['?'] * len(old_chat_ids))
            cursor.execute(f"DELETE FROM chats WHERE id IN ({placeholders})", old_chat_ids)
            
            # 提交事务
            conn.commit()
            logger.info(f"成功清理了 {chat_count} 个聊天及其相关消息")
            
            # 压缩数据库（回收空间）
            cursor.execute("VACUUM")
            logger.info("数据库已压缩")
            
        except Exception as e:
            # 出错时回滚
            conn.rollback()
            logger.error(f"清理过程中发生错误，已回滚: {str(e)}")
            raise
        finally:
            # 关闭连接
            conn.close()
            
    except Exception as e:
        logger.error(f"执行清理任务时发生错误: {str(e)}")

if __name__ == "__main__":
    try:
        # 默认清理30天前的聊天记录
        days_to_keep = 30
        
        # 如果命令行提供了参数，则使用该参数作为保留天数
        if len(sys.argv) > 1:
            try:
                days_to_keep = int(sys.argv[1])
                if days_to_keep <= 0:
                    raise ValueError("保留天数必须大于0")
            except ValueError:
                logger.error(f"无效的天数参数: {sys.argv[1]}")
                sys.exit(1)
        
        logger.info(f"开始清理{days_to_keep}天前的聊天记录")
        cleanup_old_chats(days=days_to_keep)
        logger.info("清理任务完成")
    except Exception as e:
        logger.error(f"程序执行失败: {str(e)}")
        sys.exit(1) 