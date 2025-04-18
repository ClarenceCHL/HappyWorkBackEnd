import sqlite3
import os
import logging
from datetime import datetime

# 配置日志记录
log_file = os.path.join(os.path.dirname(__file__), 'migrate.log')
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 数据库文件路径
db_file = os.path.join(os.path.dirname(__file__), 'users.db')

def migrate():
    """将 is_paid 列添加到 users 表中"""
    conn = None
    try:
        # 连接数据库
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        logging.info("Connected to database.")
        
        # 检查 is_paid 列是否已存在
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'is_paid' in columns:
            logging.info("Column 'is_paid' already exists in table 'users'. No migration needed.")
            print("Column 'is_paid' already exists. No migration needed.")
            return

        # 添加 is_paid 列，设置默认值为 False (0 for SQLite Boolean)
        logging.info("Adding column 'is_paid' to table 'users'...")
        cursor.execute("ALTER TABLE users ADD COLUMN is_paid BOOLEAN DEFAULT 0 NOT NULL")
        logging.info("Column 'is_paid' added successfully.")
        print("Column 'is_paid' added successfully.")
        
        # 提交更改
        conn.commit()
        logging.info("Changes committed.")
        
    except sqlite3.Error as e:
        logging.error(f"Database error during migration: {e}")
        print(f"Database error: {e}")
        if conn:
            conn.rollback()
            logging.info("Changes rolled back due to error.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during migration: {e}")
        print(f"An unexpected error occurred: {e}")
        if conn:
            conn.rollback()
            logging.info("Changes rolled back due to error.")
    finally:
        # 关闭数据库连接
        if conn:
            conn.close()
            logging.info("Database connection closed.")

if __name__ == '__main__':
    print(f"Starting migration to add 'is_paid' column...")
    logging.info(f"=== Starting migration: {os.path.basename(__file__)} ===")
    migrate()
    logging.info(f"=== Finished migration: {os.path.basename(__file__)} ===")
    print("Migration finished.") 