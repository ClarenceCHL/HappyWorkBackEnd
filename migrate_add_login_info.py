import sqlite3
import os
import logging
from datetime import datetime

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('migrate.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)

def migrate_add_login_info():
    """向users表添加登录IP和时间字段"""
    try:
        logger.info("开始迁移：添加用户登录IP和时间字段")
        
        # 检查数据库文件是否存在
        if not os.path.exists('users.db'):
            logger.error("数据库文件不存在！")
            return False
            
        # 连接数据库
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # 检查users表是否存在
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if not cursor.fetchone():
            logger.error("users表不存在！")
            conn.close()
            return False
        
        # 检查是否已存在last_login_ip列
        need_add_ip = True
        need_add_time = True
        
        try:
            cursor.execute("SELECT last_login_ip FROM users LIMIT 1")
            logger.info("last_login_ip字段已存在，无需添加")
            need_add_ip = False
        except sqlite3.OperationalError:
            logger.info("需要添加last_login_ip字段")
        
        try:
            cursor.execute("SELECT last_login_time FROM users LIMIT 1")
            logger.info("last_login_time字段已存在，无需添加")
            need_add_time = False
        except sqlite3.OperationalError:
            logger.info("需要添加last_login_time字段")
        
        # 添加缺少的列
        if need_add_ip:
            logger.info("添加last_login_ip字段到users表")
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_ip TEXT")
            conn.commit()
            logger.info("成功添加last_login_ip字段")
            
        if need_add_time:
            logger.info("添加last_login_time字段到users表")
            cursor.execute("ALTER TABLE users ADD COLUMN last_login_time TIMESTAMP")
            conn.commit()
            logger.info("成功添加last_login_time字段")
        
        if not need_add_ip and not need_add_time:
            logger.info("所有字段都已存在，无需迁移")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"迁移失败: {str(e)}")
        return False

if __name__ == "__main__":
    success = migrate_add_login_info()
    if success:
        print("迁移完成！")
    else:
        print("迁移失败，请查看日志获取详细信息。") 