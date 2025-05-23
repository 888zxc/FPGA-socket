#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
from matplotlib.font_manager import FontProperties
import os
import sys
import pandas as pd
from database import Database
import time
from datetime import datetime, timedelta


class AdminApp:
    def __init__(self, root):
        self.root = root
        self.root.title("聊天应用管理后台")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        # 设置颜色主题
        self.bg_color = "#f0f0f0"
        self.accent_color = "#3f51b5"
        self.text_color = "#333333"
        self.root.configure(bg=self.bg_color)
        
        self.setup_chinese_font()
        # 连接数据库
        self.db = Database()

        # 创建UI
        self.create_ui()

        # 初始加载数据
        self.load_data()
    
    def setup_chinese_font (self):
        """设置Matplotlib中文字体支持"""
        try:
            # 使用当前目录下的字体文件
            import os
            font_path = os.path.join(os.path.dirname(__file__), 'font', 'songti.ttf')
            
            if os.path.exists(font_path):
                self.chinese_font = FontProperties(fname=font_path)
                matplotlib.rcParams['font.family'] = ['sans-serif']
                matplotlib.rcParams['font.sans-serif'] = [font_path, 'Arial', 'Helvetica']
                print(f"成功加载字体: {font_path}")
            else:
                # 如果找不到指定字体文件，使用系统默认字体
                raise FileNotFoundError(f"未找到字体文件: {font_path}")
        
        except Exception as e:
            print(f"加载指定字体失败: {e}")
            # 使用matplotlib默认配置尝试支持中文
            matplotlib.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans', 'Arial Unicode MS', 'sans-serif']
            matplotlib.rcParams['axes.unicode_minus'] = False
            self.chinese_font = FontProperties(family='sans-serif')
            print("使用系统默认字体")
            
    def create_ui(self):
        # 创建选项卡
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # 消息管理选项卡
        self.messages_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.messages_frame, text="消息管理")
        self.setup_messages_tab()

        # 用户管理选项卡
        self.users_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.users_frame, text="用户管理")
        self.setup_users_tab()

        # 统计分析选项卡
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="统计分析")
        self.setup_stats_tab()

        # 底部状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = tk.Label(
            self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 设置刷新按钮
        refresh_button = tk.Button(
            self.root,
            text="刷新数据",
            command=self.load_data,
            bg=self.accent_color,
            fg="white",
            padx=10,
        )
        refresh_button.pack(side=tk.BOTTOM, pady=5)

    def setup_messages_tab(self):
        # 创建工具栏
        toolbar = tk.Frame(self.messages_frame, bg=self.bg_color)
        toolbar.pack(fill="x", pady=5)

        # 搜索框
        tk.Label(toolbar, text="搜索:", bg=self.bg_color).pack(side="left", padx=5)
        self.search_entry = tk.Entry(toolbar, width=30)
        self.search_entry.pack(side="left", padx=5)

        search_button = tk.Button(
            toolbar,
            text="搜索",
            command=self.search_messages,
            bg=self.accent_color,
            fg="white",
        )
        search_button.pack(side="left", padx=5)

        # 删除按钮
        delete_button = tk.Button(
            toolbar,
            text="删除所选",
            command=self.delete_selected_messages,
            bg="#f44336",
            fg="white",
        )
        delete_button.pack(side="right", padx=5)

        # 创建表格
        columns = ("ID", "用户名", "内容", "IP地址", "时间")
        self.messages_tree = ttk.Treeview(
            self.messages_frame, columns=columns, show="headings"
        )

        # 设置列宽和标题
        self.messages_tree.column("ID", width=50)
        self.messages_tree.column("用户名", width=120)
        self.messages_tree.column("内容", width=400)
        self.messages_tree.column("IP地址", width=120)
        self.messages_tree.column("时间", width=150)

        for col in columns:
            self.messages_tree.heading(col, text=col)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(
            self.messages_frame, orient="vertical", command=self.messages_tree.yview
        )
        self.messages_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.messages_tree.pack(fill="both", expand=True)

    def setup_users_tab(self):
        # 创建工具栏
        toolbar = tk.Frame(self.users_frame, bg=self.bg_color)
        toolbar.pack(fill="x", pady=5)

        # 搜索框
        tk.Label(toolbar, text="搜索:", bg=self.bg_color).pack(side="left", padx=5)
        self.user_search_entry = tk.Entry(toolbar, width=30)
        self.user_search_entry.pack(side="left", padx=5)

        search_button = tk.Button(
            toolbar,
            text="搜索",
            command=self.search_users,
            bg=self.accent_color,
            fg="white",
        )
        search_button.pack(side="left", padx=5)

        # 删除按钮
        delete_button = tk.Button(
            toolbar,
            text="删除所选",
            command=self.delete_selected_users,
            bg="#f44336",
            fg="white",
        )
        delete_button.pack(side="right", padx=5)

        # 创建表格
        columns = ("ID", "用户名", "IP地址", "最后活动时间", "注册时间")
        self.users_tree = ttk.Treeview(
            self.users_frame, columns=columns, show="headings"
        )

        # 设置列宽和标题
        self.users_tree.column("ID", width=50)
        self.users_tree.column("用户名", width=150)
        self.users_tree.column("IP地址", width=150)
        self.users_tree.column("最后活动时间", width=150)
        self.users_tree.column("注册时间", width=150)

        for col in columns:
            self.users_tree.heading(col, text=col)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(
            self.users_frame, orient="vertical", command=self.users_tree.yview
        )
        self.users_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.users_tree.pack(fill="both", expand=True)

    def setup_stats_tab(self):
        # 创建统计信息显示区域
        info_frame = tk.LabelFrame(
            self.stats_frame, text="基本统计", bg=self.bg_color, padx=10, pady=10
        )
        info_frame.pack(fill="x", pady=10)

        # 统计信息标签
        self.total_messages_var = tk.StringVar(value="总消息数: 加载中...")
        tk.Label(
            info_frame, textvariable=self.total_messages_var, bg=self.bg_color
        ).grid(row=0, column=0, sticky="w", padx=5, pady=2)

        self.total_users_var = tk.StringVar(value="总用户数: 加载中...")
        tk.Label(info_frame, textvariable=self.total_users_var, bg=self.bg_color).grid(
            row=0, column=1, sticky="w", padx=5, pady=2
        )

        # 图表区域
        charts_frame = tk.Frame(self.stats_frame, bg=self.bg_color)
        charts_frame.pack(fill="both", expand=True, pady=10)

        # 图表选项
        options_frame = tk.Frame(charts_frame, bg=self.bg_color)
        options_frame.pack(fill="x")

        tk.Label(options_frame, text="选择图表:", bg=self.bg_color).pack(
            side="left", padx=5
        )
        self.chart_type = tk.StringVar(value="用户活跃度")
        chart_options = ["用户活跃度", "每日消息量", "消息长度分布"]
        chart_menu = ttk.Combobox(
            options_frame,
            textvariable=self.chart_type,
            values=chart_options,
            state="readonly",
        )
        chart_menu.pack(side="left", padx=5)
        chart_menu.bind("<<ComboboxSelected>>", self.update_chart)

        # 图表容器
        self.chart_frame = tk.Frame(charts_frame, bg="white")
        self.chart_frame.pack(fill="both", expand=True, pady=10)

        # 活跃用户表格
        active_users_frame = tk.LabelFrame(
            self.stats_frame, text="最活跃用户", bg=self.bg_color, padx=10, pady=10
        )
        active_users_frame.pack(fill="x", pady=10)

        columns = ("排名", "用户名", "消息数")
        self.active_users_tree = ttk.Treeview(
            active_users_frame, columns=columns, show="headings", height=5
        )

        for col, width in zip(columns, [50, 200, 100]):
            self.active_users_tree.column(col, width=width)
            self.active_users_tree.heading(col, text=col)

        self.active_users_tree.pack(fill="x")

    def load_data(self):
        # 更新状态
        self.status_var.set("正在加载数据...")
        self.root.update_idletasks()

        # 加载消息数据
        self.load_messages()

        # 加载用户数据
        self.load_users()

        # 加载统计数据
        self.load_stats()

        # 更新状态
        self.status_var.set("数据加载完成")

    def load_messages(self):
        # 清空现有数据
        for item in self.messages_tree.get_children():
            self.messages_tree.delete(item)

        # 获取消息数据
        messages = self.db.get_messages(limit=100)

        # 填充表格
        for idx, message in enumerate(messages, 1):
            timestamp_str = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(message["timestamp"]))
                if message["timestamp"]
                else ""
            )
            self.messages_tree.insert(
                "",
                "end",
                values=(
                    idx,
                    message["username"],
                    message["content"],
                    message["ip_address"],
                    timestamp_str,
                ),
            )

    def load_users(self):
        # 清空现有数据
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)

        # 获取用户数据
        users = self.db.get_users()

        # 填充表格
        for idx, user in enumerate(users, 1):
            last_seen_str = (
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(user["last_seen"]))
                if user["last_seen"]
                else "未知"
            )
            created_at_str = "N/A"  # 在真实数据库中应该有此字段
            self.users_tree.insert(
                "",
                "end",
                values=(
                    idx,
                    user["username"],
                    user["ip_address"],
                    last_seen_str,
                    created_at_str,
                ),
            )

    def load_stats(self):
        # 获取统计数据
        stats = self.db.get_stats()

        # 更新基本统计信息
        self.total_messages_var.set(f"总消息数: {stats.get('total_messages', 0)}")
        self.total_users_var.set(f"总用户数: {stats.get('total_users', 0)}")

        # 更新活跃用户表格
        for item in self.active_users_tree.get_children():
            self.active_users_tree.delete(item)

        for idx, user in enumerate(stats.get("top_users", []), 1):
            self.active_users_tree.insert(
                "", "end", values=(idx, user["username"], user["message_count"])
            )

        # 更新图表
        self.update_chart()

    def update_chart(self, event=None):
        chart_type = self.chart_type.get()

        # 清空现有图表
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        # 创建新图表
        fig = plt.Figure(figsize=(8, 4), dpi=100)
        ax = fig.add_subplot(111)

        if chart_type == "用户活跃度":
            self.draw_user_activity_chart(ax)
        elif chart_type == "每日消息量":
            self.draw_daily_messages_chart(ax)
        elif chart_type == "消息长度分布":
            self.draw_message_length_chart(ax)

        # 显示图表
        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    def draw_user_activity_chart(self, ax):
        # 获取数据
        stats = self.db.get_stats()
        users = [user["username"] for user in stats.get("top_users", [])]
        message_counts = [user["message_count"] for user in stats.get("top_users", [])]

        if not users:
            ax.text(0.5, 0.5, "没有足够的数据", ha="center", va="center")
            return

        # 绘制柱状图
        bars = ax.bar(users, message_counts, color=self.accent_color)

        # 添加数据标签
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height + 0.1,
                f"{height}",
                ha="center",
                va="bottom",
            )

        ax.set_title("用户活跃度", fontproperties=self.chinese_font)
        ax.set_xlabel("用户名", fontproperties=self.chinese_font)
        ax.set_ylabel("消息数", fontproperties=self.chinese_font)
        ax.set_xticklabels(users, rotation=45, ha="right", fontproperties=self.chinese_font)

    def draw_daily_messages_chart(self, ax):
        # 获取最近7天的消息
        messages = self.db.get_messages(limit=1000)

        if not messages:
            ax.text(0.5, 0.5, "没有足够的数据", ha="center", va="center")
            return

        # 按日期分组
        df = pd.DataFrame(messages)
        if "timestamp" in df.columns:
            df["date"] = pd.to_datetime(df["timestamp"], unit="s").dt.date
            daily_counts = df.groupby("date").size()

            # 确保至少显示7天数据
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=6)
            date_range = pd.date_range(start=start_date, end=end_date)
            date_range = [d.date() for d in date_range]

            # 合并数据
            complete_data = pd.Series(0, index=date_range)
            for date, count in daily_counts.items():
                if date in date_range:
                    complete_data[date] = count

            # 绘制折线图
            ax.plot(
                complete_data.index,
                complete_data.values,
                marker="o",
                linestyle="-",
                color=self.accent_color,
            )
            ax.set_title("每日消息量", fontproperties=self.chinese_font)
            ax.set_xlabel("日期", fontproperties=self.chinese_font)
            ax.set_ylabel("消息数", fontproperties=self.chinese_font)
            ax.grid(True, linestyle="--", alpha=0.7)

            # 设置日期格式
            date_format = "%m-%d"
            date_labels = [d.strftime(date_format) for d in complete_data.index]
            ax.set_xticklabels(date_labels, rotation=45)
        else:
            ax.text(0.5, 0.5, "没有时间戳数据", ha="center", va="center", fontproperties=self.chinese_font)

    def draw_message_length_chart(self, ax):
        # 获取消息数据
        messages = self.db.get_messages(limit=1000)

        if not messages:
            ax.text(0.5, 0.5, "没有足够的数据", ha="center", va="center", fontproperties=self.chinese_font)
            return

        # 计算消息长度
        message_lengths = [len(msg["content"]) for msg in messages]

        # 绘制直方图
        ax.hist(message_lengths, bins=20, color=self.accent_color, alpha=0.7)
        ax.set_title("消息长度分布", fontproperties=self.chinese_font)
        ax.set_xlabel("消息长度 (字符)", fontproperties=self.chinese_font)
        ax.set_ylabel("消息数", fontproperties=self.chinese_font)
        ax.grid(True, linestyle="--", alpha=0.7)

    def search_messages(self):
        search_term = self.search_entry.get().strip()
        if not search_term:
            # 如果搜索框为空，重新加载所有数据
            self.load_messages()
            return

        # 在实际应用中，应该通过数据库查询实现搜索功能
        # 这里简单实现为在已加载的数据中过滤
        for item in self.messages_tree.get_children():
            values = self.messages_tree.item(item, "values")
            if search_term.lower() in str(values).lower():
                # 保留匹配项
                pass
            else:
                # 移除不匹配项
                self.messages_tree.delete(item)

    def search_users(self):
        search_term = self.user_search_entry.get().strip()
        if not search_term:
            # 如果搜索框为空，重新加载所有数据
            self.load_users()
            return

        # 在实际应用中，应该通过数据库查询实现搜索功能
        # 这里简单实现为在已加载的数据中过滤
        for item in self.users_tree.get_children():
            values = self.users_tree.item(item, "values")
            if search_term.lower() in str(values).lower():
                # 保留匹配项
                pass
            else:
                # 移除不匹配项
                self.users_tree.delete(item)

    def delete_selected_messages(self):
        selected_items = self.messages_tree.selection()
        if not selected_items:
            messagebox.showinfo("提示", "请先选择要删除的消息")
            return

        if messagebox.askyesno("确认", "确定要删除选中的消息吗？"):
            # 在实际应用中，这里应该调用数据库方法删除实际记录
            # 这里仅从界面上移除
            for item in selected_items:
                self.messages_tree.delete(item)

            messagebox.showinfo("成功", f"已删除 {len(selected_items)} 条消息")

    def delete_selected_users(self):
        selected_items = self.users_tree.selection()
        if not selected_items:
            messagebox.showinfo("提示", "请先选择要删除的用户")
            return

        if messagebox.askyesno(
            "确认", "确定要删除选中的用户吗？所有相关消息也会被删除。"
        ):
            # 在实际应用中，这里应该调用数据库方法删除实际记录
            # 这里仅从界面上移除
            for item in selected_items:
                self.users_tree.delete(item)

            messagebox.showinfo("成功", f"已删除 {len(selected_items)} 个用户及其消息")


if __name__ == "__main__":
    root = tk.Tk()
    app = AdminApp(root)
    root.mainloop()
