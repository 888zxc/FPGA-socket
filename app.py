#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket
import json
import time
from database import Database


class ChatApp:
    def __init__ (self, root):
        self.root = root
        self.root.title("聊天应用")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # 设置颜色主题
        self.bg_color = "#f5f5f5"
        self.accent_color = "#4a6ea9"
        self.text_color = "#333333"
        self.root.configure(bg=self.bg_color)
        
        # 连接数据库
        self.db = Database()
        
        # 网络变量
        self.socket = None
        self.running = False
        self.is_server = False
        self.protocol = "UDP"  # 新增协议选择
        self.clients = {}  # 用于服务器记录客户端
        self.tcp_clients = []  # TCP客户端连接列表
        self.username = "匿名用户"
        self.server_address = None
        
        # 创建UI
        self.create_ui()
    
    def create_ui (self):
        # 创建主框架
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 左侧面板 - 连接设置和在线用户列表
        left_frame = tk.Frame(main_frame, bg=self.bg_color, width=200)
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        left_frame.pack_propagate(False)
        
        # 连接设置区域
        conn_frame = tk.LabelFrame(
                left_frame,
                text="连接设置",
                bg=self.bg_color,
                fg=self.text_color,
                padx=5,
                pady=5,
        )
        conn_frame.pack(fill="x", pady=(0, 10))
        
        # 协议选择
        protocol_frame = tk.Frame(conn_frame, bg=self.bg_color)
        protocol_frame.pack(fill="x", pady=5)
        tk.Label(protocol_frame, text="协议:", bg=self.bg_color, fg=self.text_color).pack(side="left")
        
        self.protocol_var = tk.StringVar(value="UDP")
        protocol_combo = ttk.Combobox(
                protocol_frame,
                textvariable=self.protocol_var,
                values=["UDP", "TCP"],
                state="readonly",
                width=8
        )
        protocol_combo.pack(side="left", padx=5)
        protocol_combo.bind("<<ComboboxSelected>>", self.on_protocol_change)
        
        # 模式选择
        mode_frame = tk.Frame(conn_frame, bg=self.bg_color)
        mode_frame.pack(fill="x", pady=5)
        
        self.mode_var = tk.StringVar(value="client")
        tk.Radiobutton(
                mode_frame,
                text="服务器",
                variable=self.mode_var,
                value="server",
                bg=self.bg_color,
                fg=self.text_color,
                selectcolor=self.accent_color,
                command=self.toggle_mode,
        ).pack(side="left")
        tk.Radiobutton(
                mode_frame,
                text="客户端",
                variable=self.mode_var,
                value="client",
                bg=self.bg_color,
                fg=self.text_color,
                selectcolor=self.accent_color,
                command=self.toggle_mode,
        ).pack(side="left")
        
        # IP输入框
        ip_frame = tk.Frame(conn_frame, bg=self.bg_color)
        ip_frame.pack(fill="x", pady=2)
        tk.Label(ip_frame, text="IP地址:", bg=self.bg_color, fg=self.text_color).pack(
                side="left"
        )
        self.ip_entry = tk.Entry(ip_frame)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # 端口输入框
        port_frame = tk.Frame(conn_frame, bg=self.bg_color)
        port_frame.pack(fill="x", pady=2)
        tk.Label(port_frame, text="端口:", bg=self.bg_color, fg=self.text_color).pack(
                side="left"
        )
        self.port_entry = tk.Entry(port_frame, width=8)
        self.port_entry.insert(0, "8000")
        self.port_entry.pack(side="left", padx=5)
        
        # 用户名输入框
        name_frame = tk.Frame(conn_frame, bg=self.bg_color)
        name_frame.pack(fill="x", pady=2)
        tk.Label(name_frame, text="用户名:", bg=self.bg_color, fg=self.text_color).pack(
                side="left"
        )
        self.username_entry = tk.Entry(name_frame)
        self.username_entry.insert(0, "用户" + str(int(time.time()) % 1000))
        self.username_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # 连接按钮
        self.connect_button = tk.Button(
                conn_frame,
                text="连接",
                command=self.toggle_connection,
                bg=self.accent_color,
                fg="white",
                padx=10,
        )
        self.connect_button.pack(fill="x", pady=5)
        
        # 在线用户列表
        users_frame = tk.LabelFrame(
                left_frame,
                text="在线用户",
                bg=self.bg_color,
                fg=self.text_color,
                padx=5,
                pady=5,
        )
        users_frame.pack(fill="both", expand=True)
        
        self.users_listbox = tk.Listbox(
                users_frame,
                bg="white",
                fg=self.text_color,
                selectbackground=self.accent_color,
        )
        self.users_listbox.pack(fill="both", expand=True)
        
        # 右侧面板 - 聊天区域
        right_frame = tk.Frame(main_frame, bg=self.bg_color)
        right_frame.pack(side="left", fill="both", expand=True)
        
        # 聊天记录框
        self.chat_display = scrolledtext.ScrolledText(
                right_frame, wrap=tk.WORD, bg="white", fg=self.text_color
        )
        self.chat_display.pack(fill="both", expand=True, pady=(0, 10))
        self.chat_display.config(state=tk.DISABLED)
        
        # 输入区域框架
        input_frame = tk.Frame(right_frame, bg=self.bg_color)
        input_frame.pack(fill="x")
        
        # 消息输入框
        self.message_input = tk.Text(input_frame, wrap=tk.WORD, height=3)
        self.message_input.pack(side="left", fill="both", expand=True, padx=(0, 5))
        self.message_input.bind("<Return>", self.send_on_enter)
        
        # 发送按钮
        self.send_button = tk.Button(
                input_frame,
                text="发送",
                command=self.send_message,
                bg=self.accent_color,
                fg="white",
                width=8,
        )
        self.send_button.pack(side="right", fill="y")
        
        # 底部状态栏
        self.status_var = tk.StringVar(value="未连接")
        status_bar = tk.Label(
                self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def on_protocol_change (self, event=None):
        """协议改变时的处理"""
        self.protocol = self.protocol_var.get()
        self.log_message(f"协议已切换到: {self.protocol}")
    
    def toggle_mode (self):
        mode = self.mode_var.get()
        if mode == "server":
            self.ip_entry.config(state=tk.DISABLED)
        else:
            self.ip_entry.config(state=tk.NORMAL)
    
    def toggle_connection (self):
        if not self.running:
            self.start_connection()
        else:
            self.stop_connection()
    
    def start_connection (self):
        mode = self.mode_var.get()
        port = int(self.port_entry.get())
        self.username = self.username_entry.get()
        self.protocol = self.protocol_var.get()
        
        try:
            # 根据协议创建不同类型的socket
            if self.protocol == "TCP":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            if mode == "server":
                self.start_server(port)
            else:
                self.start_client(port)
            
            self.running = True
            self.connect_button.config(text="断开")
        
        except Exception as e:
            messagebox.showerror("连接错误", str(e))
    
    def start_server (self, port):
        """启动服务器"""
        self.socket.bind(("", port))
        self.is_server = True
        
        if self.protocol == "TCP":
            self.socket.listen(5)  # TCP需要监听
            self.log_message(f"TCP服务器已启动，端口: {port}")
            self.status_var.set(f"TCP服务器运行中 - 端口: {port}")
            # 启动TCP服务器接受连接线程
            threading.Thread(target=self.tcp_server_accept_loop, daemon=True).start()
        else:  # UDP
            self.log_message(f"UDP服务器已启动，端口: {port}")
            self.status_var.set(f"UDP服务器运行中 - 端口: {port}")
            # 启动UDP接收消息线程
            threading.Thread(target=self.udp_receive_loop, daemon=True).start()
    
    def start_client (self, port):
        """启动客户端"""
        self.server_address = (self.ip_entry.get(), port)
        self.is_server = False
        
        if self.protocol == "TCP":
            # TCP客户端直接连接
            self.socket.connect(self.server_address)
            self.log_message(f"TCP客户端已连接到 {self.server_address[0]}:{self.server_address[1]}")
            self.status_var.set(f"TCP已连接到服务器 {self.server_address[0]}:{self.server_address[1]}")
            # 启动TCP接收消息线程
            threading.Thread(target=self.tcp_client_receive_loop, daemon=True).start()
        else:  # UDP
            self.socket.bind(("", 0))  # 随机可用端口
            self.log_message(f"UDP客户端已启动，将连接到 {self.server_address[0]}:{self.server_address[1]}")
            self.status_var.set(f"UDP已连接到服务器 {self.server_address[0]}:{self.server_address[1]}")
            # 启动UDP接收消息线程
            threading.Thread(target=self.udp_receive_loop, daemon=True).start()
        
        # 发送上线通知
        self.announce_presence()
    
    def tcp_server_accept_loop (self):
        """TCP服务器接受客户端连接循环"""
        while self.running:
            try:
                client_socket, addr = self.socket.accept()
                self.tcp_clients.append(client_socket)
                self.log_message(f"TCP客户端 {addr} 已连接")
                
                # 为每个客户端启动接收线程
                threading.Thread(
                        target=self.tcp_server_handle_client,
                        args=(client_socket, addr),
                        daemon=True
                ).start()
            
            except OSError:
                if self.running:
                    self.log_message("TCP服务器接受连接错误")
                break
    
    def tcp_server_handle_client (self, client_socket, addr):
        """TCP服务器处理单个客户端"""
        while self.running:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break
                self.handle_message(data, addr, client_socket)
            except OSError:
                break
        
        # 客户端断开连接
        if client_socket in self.tcp_clients:
            self.tcp_clients.remove(client_socket)
        client_socket.close()
        self.log_message(f"TCP客户端 {addr} 已断开连接")
    
    def tcp_client_receive_loop (self):
        """TCP客户端接收消息循环"""
        while self.running:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                self.handle_message(data, self.server_address)
            except OSError:
                if self.running:
                    self.log_message("TCP连接错误，请重新连接")
                break
    
    def udp_receive_loop (self):
        """UDP接收消息循环"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self.handle_message(data, addr)
            except OSError:
                if self.running:
                    self.log_message("UDP网络错误，请重新连接")
                break
    
    def handle_message (self, data, addr, client_socket=None):
        try:
            message = json.loads(data.decode("utf-8"))
            
            # 根据消息类型处理
            if message["type"] == "chat":
                sender = message.get("username", "匿名")
                content = message.get("content", "")
                timestamp = message.get("timestamp", time.time())
                formatted_time = time.strftime("%H:%M:%S", time.localtime(timestamp))
                
                self.log_message(f"[{formatted_time}] {sender}: {content}")
                
                # 保存消息到数据库
                if self.is_server:
                    self.db.save_message(sender, content, addr[0], timestamp)
                    # 转发消息给所有客户端
                    self.broadcast_message(data, exclude_addr=addr, exclude_socket=client_socket)
            
            elif message["type"] == "join":
                username = message.get("username", "某用户")
                
                if self.is_server:
                    # 服务器记录客户端信息
                    if self.protocol == "TCP":
                        self.clients[client_socket] = {
                                "username" : username,
                                "last_seen": time.time(),
                                "addr"     : addr
                        }
                    else:  # UDP
                        self.clients[addr] = {
                                "username" : username,
                                "last_seen": time.time(),
                        }
                    
                    self.update_users_list()
                    # 发送当前在线用户列表
                    if self.protocol == "TCP":
                        self.send_users_list_tcp(client_socket)
                    else:
                        self.send_users_list_udp(addr)
                    
                    # 广播用户加入消息
                    join_broadcast = {
                            "type"     : "system",
                            "content"  : f"{username} 已加入聊天",
                            "timestamp": time.time(),
                    }
                    self.broadcast_message(json.dumps(join_broadcast).encode("utf-8"))
                
                self.log_message(f"系统: {username} 已加入聊天")
            
            elif message["type"] == "leave":
                username = message.get("username", "某用户")
                
                if self.is_server:
                    # 移除客户端信息
                    if self.protocol == "TCP" and client_socket in self.clients:
                        del self.clients[client_socket]
                    elif self.protocol == "UDP" and addr in self.clients:
                        del self.clients[addr]
                    
                    self.update_users_list()
                    
                    # 广播用户离开消息
                    leave_broadcast = {
                            "type"     : "system",
                            "content"  : f"{username} 已离开聊天",
                            "timestamp": time.time(),
                    }
                    self.broadcast_message(json.dumps(leave_broadcast).encode("utf-8"))
                
                self.log_message(f"系统: {username} 已离开聊天")
            
            elif message["type"] == "users_list":
                # 客户端接收到用户列表更新
                users = message.get("users", [])
                self.users_listbox.delete(0, tk.END)
                for user in users:
                    self.users_listbox.insert(tk.END, user)
            
            elif message["type"] == "system":
                content = message.get("content", "")
                self.log_message(f"系统: {content}")
        
        except json.JSONDecodeError:
            self.log_message(f"收到非JSON消息: {data.decode('utf-8', errors='replace')}")
        except Exception as e:
            self.log_message(f"处理消息错误: {str(e)}")
    
    def broadcast_message (self, data, exclude_addr=None, exclude_socket=None):
        """广播消息给所有客户端"""
        if not self.is_server:
            return
        
        if self.protocol == "TCP":
            # TCP广播
            for client_socket in self.tcp_clients[:]:  # 创建副本以避免修改时的问题
                if exclude_socket and client_socket == exclude_socket:
                    continue
                try:
                    client_socket.send(data)
                except Exception as e:
                    self.log_message(f"TCP发送失败: {str(e)}")
                    if client_socket in self.tcp_clients:
                        self.tcp_clients.remove(client_socket)
        else:
            # UDP广播
            for client_addr in self.clients:
                if exclude_addr and client_addr == exclude_addr:
                    continue
                try:
                    self.socket.sendto(data, client_addr)
                except Exception as e:
                    self.log_message(f"UDP发送到 {client_addr} 失败: {str(e)}")
    
    def send_users_list_tcp (self, target_socket=None):
        """TCP发送用户列表"""
        if not self.is_server:
            return
        
        users_list = {
                "type"     : "users_list",
                "users"    : [client_info["username"] for client_info in self.clients.values()],
                "timestamp": time.time(),
        }
        
        encoded_list = json.dumps(users_list).encode("utf-8")
        
        if target_socket:
            # 发送给特定客户端
            try:
                target_socket.send(encoded_list)
            except:
                pass
        else:
            # 广播给所有客户端
            self.broadcast_message(encoded_list)
    
    def send_users_list_udp (self, target_addr=None):
        """UDP发送用户列表"""
        if not self.is_server:
            return
        
        users_list = {
                "type"     : "users_list",
                "users"    : [client_info["username"] for client_info in self.clients.values()],
                "timestamp": time.time(),
        }
        
        encoded_list = json.dumps(users_list).encode("utf-8")
        
        if target_addr:
            # 发送给特定客户端
            self.socket.sendto(encoded_list, target_addr)
        else:
            # 广播给所有客户端
            self.broadcast_message(encoded_list)
    
    def update_users_list (self):
        """更新本地用户列表显示"""
        self.users_listbox.delete(0, tk.END)
        for client_info in self.clients.values():
            self.users_listbox.insert(tk.END, client_info["username"])
        
        if self.is_server:
            if self.protocol == "TCP":
                self.send_users_list_tcp()
            else:
                self.send_users_list_udp()
    
    def announce_presence (self):
        """发送上线通知"""
        join_msg = {
                "type"     : "join",
                "username" : self.username,
                "timestamp": time.time(),
        }
        encoded_msg = json.dumps(join_msg).encode("utf-8")
        
        if self.protocol == "TCP":
            try:
                self.socket.send(encoded_msg)
            except:
                pass
        else:  # UDP
            if self.server_address:
                try:
                    self.socket.sendto(encoded_msg, self.server_address)
                except:
                    pass
    
    def send_leave_message (self):
        """发送下线通知"""
        leave_msg = {
                "type"     : "leave",
                "username" : self.username,
                "timestamp": time.time(),
        }
        encoded_msg = json.dumps(leave_msg).encode("utf-8")
        
        if self.protocol == "TCP":
            try:
                self.socket.send(encoded_msg)
            except:
                pass
        else:  # UDP
            if self.server_address:
                try:
                    self.socket.sendto(encoded_msg, self.server_address)
                except:
                    pass
    
    def send_message (self):
        if not self.running:
            messagebox.showinfo("提示", "请先连接服务器")
            return
        
        message = self.message_input.get("1.0", tk.END).strip()
        if not message:
            return
        
        # 清空输入框
        self.message_input.delete("1.0", tk.END)
        
        chat_message = {
                "type"     : "chat",
                "username" : self.username,
                "content"  : message,
                "timestamp": time.time(),
        }
        
        encoded_message = json.dumps(chat_message).encode("utf-8")
        
        if self.is_server:
            # 服务器端：直接广播
            self.log_message(f"[{time.strftime('%H:%M:%S')}] {self.username}: {message}")
            self.broadcast_message(encoded_message)
            # 保存消息到数据库
            self.db.save_message(self.username, message, "server", time.time())
        else:
            # 客户端：发送给服务器
            try:
                if self.protocol == "TCP":
                    self.socket.send(encoded_message)
                else:  # UDP
                    self.socket.sendto(encoded_message, self.server_address)
            except Exception as e:
                self.log_message(f"发送失败: {str(e)}")
    
    def send_on_enter (self, event):
        # 按Enter发送消息，Shift+Enter换行
        if not event.state & 0x001:  # 没有按下Shift键
            self.send_message()
            return "break"  # 阻止默认的换行行为
    
    def stop_connection (self):
        if self.running:
            if not self.is_server:
                # 发送下线通知
                self.send_leave_message()
            
            self.running = False
            
            # 关闭TCP客户端连接
            if self.protocol == "TCP" and self.is_server:
                for client_socket in self.tcp_clients:
                    try:
                        client_socket.close()
                    except:
                        pass
                self.tcp_clients.clear()
            
            if self.socket:
                self.socket.close()
                self.socket = None
            
            self.connect_button.config(text="连接")
            self.status_var.set("未连接")
            self.log_message("已断开连接")
            self.users_listbox.delete(0, tk.END)
            self.clients.clear()
    
    def log_message (self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
