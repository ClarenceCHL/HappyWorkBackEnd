#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库迁移脚本: 添加last_activity字段到chats表，修复外键名称
"""

import sqlite3
import logging
import datetime
import sys
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'migrate.log'))
    ]
)
logger = logging.getLogger(__name__)

def migrate_database(db_path='users.db'):
    """添加last_activity字段到chats表，并修复Message表的外键名称"""
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # 开始事务
        conn.execute("BEGIN TRANSACTION")
        
        # 检查last_activity字段是否已存在
        cursor.execute("PRAGMA table_info(chats)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'last_activity' not in columns:
            logger.info("添加last_activity字段到chats表...")
            
            # 添加last_activity字段，默认值设为与created_at相同
            cursor.execute("ALTER TABLE chats ADD COLUMN last_activity TIMESTAMP")
            
            # 获取所有聊天及其最新消息时间
            cursor.execute("""
                SELECT c.id, COALESCE(MAX(m.created_at), c.created_at) as latest_activity
                FROM chats c
                LEFT JOIN messages m ON m.conversation_id = c.id
                GROUP BY c.id
            """)
            chats_data = cursor.fetchall()
            
            # 更新每个聊天的last_activity
            current_time = datetime.datetime.now().timestamp()
            for chat_id, latest_activity in chats_data:
                activity_time = latest_activity if latest_activity else current_time
                cursor.execute("UPDATE chats SET last_activity = ? WHERE id = ?", 
                             (activity_time, chat_id))
                
            logger.info(f"已更新 {len(chats_data)} 个聊天的last_activity字段")
        else:
            logger.info("last_activity字段已存在，跳过添加")
        
        # 处理外键名称问题 - 检查表结构
        cursor.execute("PRAGMA table_info(messages)")
        message_columns = [col[1] for col in cursor.fetchall()]
        
        # 如果两个字段都存在，需要合并数据
        if 'conversation_id' in message_columns and 'chat_id' in message_columns:
            logger.info("合并conversation_id和chat_id字段的数据...")
            
            # 更新chat_id为null的记录
            cursor.execute("""
                UPDATE messages 
                SET chat_id = conversation_id 
                WHERE chat_id IS NULL AND conversation_id IS NOT NULL
            """)
            affected = cursor.rowcount
            logger.info(f"已更新 {affected} 条消息记录的chat_id")
            
        # 如果只有conversation_id存在，需要重命名
        elif 'conversation_id' in message_columns and 'chat_id' not in message_columns:
            logger.info("重命名消息表的外键字段从conversation_id到chat_id...")
            
            # 创建新表
            cursor.execute("""
                CREATE TABLE messages_new (
                    id INTEGER PRIMARY KEY,
                    chat_id INTEGER,
                    role TEXT,
                    content TEXT,
                    form_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (chat_id) REFERENCES chats (id)
                )
            """)
            
            # 复制数据
            cursor.execute("""
                INSERT INTO messages_new (id, chat_id, role, content, form_data, created_at)
                SELECT id, conversation_id, role, content, form_data, created_at FROM messages
            """)
            
            # 删除旧表并重命名新表
            cursor.execute("DROP TABLE messages")
            cursor.execute("ALTER TABLE messages_new RENAME TO messages")
            
            logger.info("消息表的外键已成功重命名")
        else:
            logger.info("消息表的外键字段已经正确，无需修改")
        
        # 提交事务
        conn.commit()
        logger.info("数据库迁移成功完成")
        
    except Exception as e:
        # 出错时回滚
        conn.rollback()
        logger.error(f"迁移出错: {str(e)}")
        raise
    finally:
        # 关闭连接
        conn.close()

if __name__ == "__main__":
    try:
        logger.info("开始数据库迁移...")
        migrate_database()
        logger.info("数据库迁移完成")
    except Exception as e:
        logger.error(f"数据库迁移失败: {str(e)}")
        sys.exit(1) 