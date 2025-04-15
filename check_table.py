import sqlite3

def check_table_structure():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        # 获取表结构
        cursor.execute("PRAGMA table_info(messages)")
        columns = cursor.fetchall()
        
        print("当前 messages 表的结构：")
        for column in columns:
            print(f"列名: {column[1]}, 类型: {column[2]}")
            
    except Exception as e:
        print(f"检查表结构时发生错误: {str(e)}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_table_structure() 