#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
import sys


def start_chat_app():
    from app import ChatApp

    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()


def start_admin_app():
    from admin import AdminApp

    root = tk.Tk()
    app = AdminApp(root)
    root.mainloop()


class LauncherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("聊天应用启动器")
        self.root.geometry("400x300")
        self.root.configure(bg="#f5f5f5")

        self.create_ui()

    def create_ui(self):
        # Logo标题
        title_label = tk.Label(
            self.root,
            text="WiFi聊天应用",
            font=("Arial", 24, "bold"),
            bg="#f5f5f5",
            fg="#4a6ea9",
        )
        title_label.pack(pady=20)

        desc_label = tk.Label(
            self.root,
            text="选择要启动的应用模式:",
            bg="#f5f5f5",
            fg="#333333",
            font=("Arial", 12),
        )
        desc_label.pack(pady=10)

        # 按钮框架
        btn_frame = tk.Frame(self.root, bg="#f5f5f5")
        btn_frame.pack(pady=20)

        # 聊天应用按钮
        chat_btn = tk.Button(
            btn_frame,
            text="启动聊天应用",
            command=self.launch_chat,
            bg="#4a6ea9",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=10,
        )
        chat_btn.grid(row=0, column=0, padx=10)

        # 管理后台按钮
        admin_btn = tk.Button(
            btn_frame,
            text="启动管理后台",
            command=self.launch_admin,
            bg="#7e57c2",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=10,
        )
        admin_btn.grid(row=0, column=1, padx=10)

        # 版本信息
        version_label = tk.Label(
            self.root, text="版本 1.0.0", bg="#f5f5f5", fg="#999999"
        )
        version_label.pack(side=tk.BOTTOM, pady=10)

    def launch_chat(self):
        self.root.destroy()
        start_chat_app()

    def launch_admin(self):
        self.root.destroy()
        start_admin_app()


if __name__ == "__main__":
    # 处理命令行参数
    if len(sys.argv) > 1:
        if sys.argv[1] == "chat":
            start_chat_app()
        elif sys.argv[1] == "admin":
            start_admin_app()
        else:
            print("无效的参数。使用方式: python main.py [chat|admin]")
    else:
        # 无参数时启动选择器
        root = tk.Tk()
        app = LauncherApp(root)
        root.mainloop()
