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

def migrate_add_admin_field():
    """向users表添加is_admin字段"""
    try:
        logger.info("开始迁移：添加is_admin字段")
        
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
        
        # 检查是否已存在is_admin列
        try:
            cursor.execute("SELECT is_admin FROM users LIMIT 1")
            logger.info("is_admin字段已存在，无需添加")
            conn.close()
            return True
        except sqlite3.OperationalError:
            # 列不存在，添加is_admin列
            logger.info("添加is_admin字段到users表")
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
            conn.commit()
            logger.info("成功添加is_admin字段")
            
        # 添加管理员账户（可选）
        admin_email = input("请输入要设置为管理员的邮箱 (直接回车跳过): ").strip()
        if admin_email:
            cursor.execute("UPDATE users SET is_admin = 1 WHERE email = ?", (admin_email,))
            affected = cursor.rowcount
            conn.commit()
            
            if affected > 0:
                logger.info(f"已将 {admin_email} 设置为管理员")
            else:
                logger.warning(f"未找到邮箱为 {admin_email} 的用户")
        
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"迁移失败: {str(e)}")
        return False

if __name__ == "__main__":
    success = migrate_add_admin_field()
    if success:
        print("迁移完成！")
    else:
        print("迁移失败，请查看日志获取详细信息。") 