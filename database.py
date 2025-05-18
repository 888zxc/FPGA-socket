# -*- coding: utf-8 -*-
import mysql.connector
import time
import json
from datetime import datetime


class Database:
    def __init__(self, host="localhost", user="root", password="aini", database="chat_app"):
        """初始化数据库连接和创建必要的表"""
        try:
            # 连接到MySQL服务器
            self.connection = mysql.connector.connect(
                host=host, user=user, passwd=password
            )
            self.cursor = self.connection.cursor()

            # 创建数据库（如果不存在）
            self.cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
            self.cursor.execute(f"USE {database}")

            # 创建消息表
            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    content TEXT NOT NULL,
                    ip_address VARCHAR(50),
                    timestamp DATETIME NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # 创建用户表
            self.cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    ip_address VARCHAR(50),
                    last_seen DATETIME,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            self.connection.commit()
            print("数据库连接成功，表已创建或已存在")

        except mysql.connector.Error as err:
            print(f"数据库错误: {err}")
            self.connection = None

    def save_message(self, username, content, ip_address, timestamp=None):
        """保存聊天消息到数据库"""
        if not self.connection:
            print("数据库未连接")
            return False

        if not timestamp:
            timestamp = time.time()

        timestamp_dt = datetime.fromtimestamp(timestamp)

        try:
            query = """
                INSERT INTO messages (username, content, ip_address, timestamp)
                VALUES (%s, %s, %s, %s)
            """
            values = (username, content, ip_address, timestamp_dt)
            self.cursor.execute(query, values)

            # 更新用户最后活动时间
            self.update_user(username, ip_address, timestamp_dt)

            self.connection.commit()
            return True
        except mysql.connector.Error as err:
            print(f"保存消息错误: {err}")
            return False

    def update_user(self, username, ip_address, last_seen):
        """更新或创建用户记录"""
        if not self.connection:
            return False

        try:
            # 检查用户是否存在
            self.cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            user_exists = self.cursor.fetchone()

            if user_exists:
                # 更新现有用户
                query = """
                    UPDATE users SET ip_address = %s, last_seen = %s
                    WHERE username = %s
                """
                values = (ip_address, last_seen, username)
            else:
                # 创建新用户
                query = """
                    INSERT INTO users (username, ip_address, last_seen)
                    VALUES (%s, %s, %s)
                """
                values = (username, ip_address, last_seen)

            self.cursor.execute(query, values)
            self.connection.commit()
            return True
        except mysql.connector.Error as err:
            print(f"更新用户错误: {err}")
            return False

    def get_messages(self, limit=50, offset=0):
        """获取最近的聊天记录"""
        if not self.connection:
            return []

        try:
            query = """
                SELECT username, content, ip_address, timestamp
                FROM messages
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
            """
            self.cursor.execute(query, (limit, offset))
            results = self.cursor.fetchall()

            messages = []
            for row in results:
                username, content, ip_address, timestamp = row
                messages.append(
                    {
                        "username": username,
                        "content": content,
                        "ip_address": ip_address,
                        "timestamp": timestamp.timestamp(),
                    }
                )

            return messages
        except mysql.connector.Error as err:
            print(f"获取消息错误: {err}")
            return []

    def get_users(self):
        """获取所有用户信息"""
        if not self.connection:
            return []

        try:
            query = """
                SELECT username, ip_address, last_seen
                FROM users
                ORDER BY last_seen DESC
            """
            self.cursor.execute(query)
            results = self.cursor.fetchall()

            users = []
            for row in results:
                username, ip_address, last_seen = row
                users.append(
                    {
                        "username": username,
                        "ip_address": ip_address,
                        "last_seen": last_seen.timestamp() if last_seen else None,
                    }
                )

            return users
        except mysql.connector.Error as err:
            print(f"获取用户错误: {err}")
            return []

    def get_stats(self):
        """获取统计信息"""
        if not self.connection:
            return {}

        stats = {}

        try:
            # 消息总数
            self.cursor.execute("SELECT COUNT(*) FROM messages")
            stats["total_messages"] = self.cursor.fetchone()[0]

            # 用户总数
            self.cursor.execute("SELECT COUNT(*) FROM users")
            stats["total_users"] = self.cursor.fetchone()[0]

            # 最活跃用户
            self.cursor.execute(
                """
                SELECT username, COUNT(*) as message_count
                FROM messages
                GROUP BY username
                ORDER BY message_count DESC
                LIMIT 5
            """
            )
            stats["top_users"] = [
                {"username": row[0], "message_count": row[1]}
                for row in self.cursor.fetchall()
            ]

            return stats
        except mysql.connector.Error as err:
            print(f"获取统计错误: {err}")
            return {}

    def close(self):
        """关闭数据库连接"""
        if self.connection:
            self.cursor.close()
            self.connection.close()
            print("数据库连接已关闭")
