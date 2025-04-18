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
    """将 has_pdf 和 pdf_storage_path 列添加到 users 表中"""
    conn = None
    try:
        # 连接数据库
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        logging.info("Connected to database for PDF fields migration.")
        
        # 检查列是否已存在
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        added_columns = []
        
        # 添加 has_pdf 列
        if 'has_pdf' not in columns:
            logging.info("Adding column 'has_pdf' to table 'users'...")
            cursor.execute("ALTER TABLE users ADD COLUMN has_pdf BOOLEAN DEFAULT 0 NOT NULL")
            logging.info("Column 'has_pdf' added successfully.")
            print("Column 'has_pdf' added successfully.")
            added_columns.append('has_pdf')
        else:
            logging.info("Column 'has_pdf' already exists.")
            print("Column 'has_pdf' already exists.")

        # 添加 pdf_storage_path 列
        if 'pdf_storage_path' not in columns:
            logging.info("Adding column 'pdf_storage_path' to table 'users'...")
            cursor.execute("ALTER TABLE users ADD COLUMN pdf_storage_path STRING NULL")
            logging.info("Column 'pdf_storage_path' added successfully.")
            print("Column 'pdf_storage_path' added successfully.")
            added_columns.append('pdf_storage_path')
        else:
            logging.info("Column 'pdf_storage_path' already exists.")
            print("Column 'pdf_storage_path' already exists.")

        # 如果有添加新列，则提交更改
        if added_columns:
            conn.commit()
            logging.info(f"Changes committed for columns: {', '.join(added_columns)}.")
        else:
            logging.info("No new columns were added. No commit needed.")
            print("No migration needed as columns already exist.")
            
    except sqlite3.Error as e:
        logging.error(f"Database error during PDF fields migration: {e}")
        print(f"Database error: {e}")
        if conn:
            conn.rollback()
            logging.info("Changes rolled back due to error.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during PDF fields migration: {e}")
        print(f"An unexpected error occurred: {e}")
        if conn:
            conn.rollback()
            logging.info("Changes rolled back due to error.")
    finally:
        # 关闭数据库连接
        if conn:
            conn.close()
            logging.info("Database connection closed after PDF fields migration.")

if __name__ == '__main__':
    print(f"Starting migration to add PDF related columns...")
    logging.info(f"=== Starting migration: {os.path.basename(__file__)} ===")
    migrate()
    logging.info(f"=== Finished migration: {os.path.basename(__file__)} ===")
    print("Migration finished.") 