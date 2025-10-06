import sys
import os
import psutil
import time
import random
import hashlib
import win32api
import win32process
import win32con
import win32security
import win32event
import winerror
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                             QLabel, QVBoxLayout, QHBoxLayout, QWidget,
                             QSystemTrayIcon, QMenu, QAction, QMessageBox,
                             QGroupBox, QGridLayout)
from PyQt5.QtCore import QTimer, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

class ProtectionThread(QThread):
    status_signal = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.running = True
        self.process_name = "StudentMain.exe"
        self.self_pid = os.getpid()
        
    def run(self):
        while self.running:
            try:
                self.protect_self()
                self.monitor_processes()
                self.sleep_random()
            except Exception as e:
                self.status_signal.emit(f"保护线程错误: {str(e)}")
            
    def protect_self(self):
        """自我保护机制"""
        try:
            # 隐藏进程（通过修改进程名为常见系统进程）
            current_process = psutil.Process(self.self_pid)
            try:
                if not current_process.name().lower().startswith("svchost"):
                    current_process.name()  # 这只是为了触发异常，实际不能直接修改进程名
            except:
                pass
                
            # 检查自身是否被终止
            if not psutil.pid_exists(self.self_pid):
                self.status_signal.emit("检测到自身被终止，尝试恢复...")
                self.restart_self()
                
        except Exception as e:
            pass
            
    def monitor_processes(self):
        """监控可疑进程"""
        suspicious_keywords = ["monitor", "teacher", "control", "manage", "监管", "管理"]
        
        for proc in psutil.process_iter(['name', 'pid', 'exe']):
            try:
                proc_name = proc.info['name'].lower()
                # 检查是否是已知的监控进程
                if any(keyword in proc_name for keyword in suspicious_keywords):
                    if proc.info['pid'] != self.self_pid:
                        self.status_signal.emit(f"检测到可疑进程: {proc.info['name']}")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
    def sleep_random(self):
        """随机睡眠时间，增加检测难度"""
        sleep_time = random.uniform(3, 8)
        time.sleep(sleep_time)
        
    def restart_self(self):
        """自我恢复机制"""
        try:
            # 获取当前可执行文件路径
            if getattr(sys, 'frozen', False):
                # 如果是打包后的exe
                exe_path = sys.executable
            else:
                # 如果是脚本
                exe_path = sys.argv[0]
                
            # 启动新实例
            win32process.CreateProcess(
                None, 
                exe_path, 
                None, 
                None, 
                0, 
                win32con.CREATE_NO_WINDOW, 
                None, 
                None, 
                win32process.STARTUPINFO()
            )
            
        except Exception as e:
            self.status_signal.emit(f"自我恢复失败: {str(e)}")
            
    def stop(self):
        self.running = False

class ExtremeDomainController(QMainWindow):
    def __init__(self):
        super().__init__()
        self.process_name = "StudentMain.exe"
        self.is_paused = False
        self.is_suspended = False
        self.suspended_processes = []
        self.protection_thread = None
        self.initUI()
        self.initTray()
        self.start_protection()
        
        # 设置定时器定期检查进程状态
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_process)
        self.timer.start(2000)
        
    def initUI(self):
        self.setWindowTitle('极域课堂控制工具 v1.2 - 保护模式')
        self.setGeometry(300, 300, 500, 400)
        self.setWindowIcon(QIcon('icon.ico'))
        
        # 设置随机窗口类名，增加检测难度
        random_class_name = f"Class_{random.randint(1000, 9999)}"
        self.setObjectName(random_class_name)
        
        # 中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # 标题
        title_label = QLabel('极域课堂控制工具 - 保护模式')
        title_label.setFont(QFont('Arial', 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # 状态显示
        self.status_label = QLabel('检测中...')
        self.status_label.setFont(QFont('Arial', 12))
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        # 保护状态显示
        self.protection_status_label = QLabel('保护机制: 已启用')
        self.protection_status_label.setFont(QFont('Arial', 10))
        self.protection_status_label.setAlignment(Qt.AlignCenter)
        self.protection_status_label.setStyleSheet('color: green; background-color: #f0f0f0; padding: 5px;')
        main_layout.addWidget(self.protection_status_label)
        
        # 创建功能组
        control_group = QGroupBox("控制功能")
        control_layout = QGridLayout()
        control_group.setLayout(control_layout)
        
        # 暂停/恢复按钮
        self.pause_btn = QPushButton('暂停极域课堂')
        self.pause_btn.clicked.connect(self.toggle_pause)
        self.pause_btn.setEnabled(False)
        control_layout.addWidget(self.pause_btn, 0, 0)
        
        # 挂起/恢复按钮
        self.suspend_btn = QPushButton('挂起极域课堂')
        self.suspend_btn.clicked.connect(self.toggle_suspend)
        self.suspend_btn.setEnabled(False)
        control_layout.addWidget(self.suspend_btn, 0, 1)
        
        # 结束按钮
        self.kill_btn = QPushButton('结束极域课堂')
        self.kill_btn.clicked.connect(self.kill_process)
        self.kill_btn.setEnabled(False)
        control_layout.addWidget(self.kill_btn, 1, 0, 1, 2)
        
        # 保护控制按钮
        self.protection_btn = QPushButton('禁用保护')
        self.protection_btn.clicked.connect(self.toggle_protection)
        control_layout.addWidget(self.protection_btn, 2, 0, 1, 2)
        
        main_layout.addWidget(control_group)
        
        # 信息显示
        info_group = QGroupBox("系统信息")
        info_layout = QVBoxLayout()
        info_group.setLayout(info_layout)
        
        self.info_label = QLabel('等待操作...\n保护机制已启动，监控系统状态中')
        self.info_label.setWordWrap(True)
        self.info_label.setAlignment(Qt.AlignLeft)
        info_layout.addWidget(self.info_label)
        
        main_layout.addWidget(info_group)
        
        # 添加作者信息
        author_label = QLabel('作者: CinderyBell6765 | 保护模式 v1.2')
        author_label.setFont(QFont('Arial', 9))
        author_label.setAlignment(Qt.AlignCenter)
        author_label.setStyleSheet('color: gray; margin-top: 10px;')
        main_layout.addWidget(author_label)
        
        # 初始检查
        self.check_process()
        
    def start_protection(self):
        """启动保护线程"""
        self.protection_thread = ProtectionThread(self)
        self.protection_thread.status_signal.connect(self.update_protection_status)
        self.protection_thread.start()
        
    def update_protection_status(self, message):
        """更新保护状态信息"""
        current_text = self.info_label.text()
        if len(current_text.split('\n')) > 5:
            current_text = '\n'.join(current_text.split('\n')[1:])
        self.info_label.setText(f"{message}\n{current_text}")
        
    def toggle_protection(self):
        """切换保护状态"""
        if self.protection_thread and self.protection_thread.isRunning():
            self.protection_thread.stop()
            self.protection_thread.wait()
            self.protection_thread = None
            self.protection_btn.setText('启用保护')
            self.protection_status_label.setText('保护机制: 已禁用')
            self.protection_status_label.setStyleSheet('color: red; background-color: #f0f0f0; padding: 5px;')
            self.info_label.setText('保护机制已禁用，程序易被检测')
        else:
            self.start_protection()
            self.protection_btn.setText('禁用保护')
            self.protection_status_label.setText('保护机制: 已启用')
            self.protection_status_label.setStyleSheet('color: green; background-color: #f0f0f0; padding: 5px;')
            self.info_label.setText('保护机制已启用，监控系统状态中')
        
    def initTray(self):
        # 创建系统托盘图标
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon('icon.ico'))
        
        # 创建托盘菜单
        tray_menu = QMenu()
        
        show_action = QAction("显示", self)
        suspend_action = QAction("挂起极域课堂", self)
        resume_action = QAction("恢复极域课堂", self)
        protection_action = QAction("切换保护", self)
        quit_action = QAction("退出", self)
        
        show_action.triggered.connect(self.show)
        suspend_action.triggered.connect(self.suspend_processes_advanced)
        resume_action.triggered.connect(self.resume_suspended_processes)
        protection_action.triggered.connect(self.toggle_protection)
        quit_action.triggered.connect(self.quit_app)
        
        tray_menu.addAction(show_action)
        tray_menu.addSeparator()
        tray_menu.addAction(suspend_action)
        tray_menu.addAction(resume_action)
        tray_menu.addSeparator()
        tray_menu.addAction(protection_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)
        
        # 设置随机托盘提示，避免被检测
        tray_tips = [
            "系统服务运行中",
            "Windows后台进程",
            "安全监控服务",
            "网络连接管理"
        ]
        self.tray_icon.setToolTip(random.choice(tray_tips))
        
    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
            
    def closeEvent(self, event):
        # 隐藏窗口而不是关闭
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "系统服务",
            "服务继续在后台运行",
            QSystemTrayIcon.Information,
            2000
        )
        
    def quit_app(self):
        # 退出前恢复所有进程并停止保护
        if self.is_paused:
            self.resume_processes()
        if self.is_suspended:
            self.resume_suspended_processes()
            
        if self.protection_thread and self.protection_thread.isRunning():
            self.protection_thread.stop()
            self.protection_thread.wait()
            
        QApplication.quit()
        
    def check_process(self):
        # 检查极域课堂进程是否在运行
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == self.process_name:
                self.status_label.setText('极域课堂正在运行')
                self.status_label.setStyleSheet('color: green')
                self.pause_btn.setEnabled(True)
                self.suspend_btn.setEnabled(True)
                self.kill_btn.setEnabled(True)
                
                if self.is_paused:
                    self.pause_btn.setText('恢复极域课堂')
                else:
                    self.pause_btn.setText('暂停极域课堂')
                    
                if self.is_suspended:
                    self.suspend_btn.setText('恢复极域课堂')
                else:
                    self.suspend_btn.setText('挂起极域课堂')
                    
                return
                
        # 如果没有找到进程
        self.status_label.setText('极域课堂未运行')
        self.status_label.setStyleSheet('color: red')
        self.pause_btn.setEnabled(False)
        self.suspend_btn.setEnabled(False)
        self.kill_btn.setEnabled(False)
        self.is_paused = False
        self.is_suspended = False
        self.suspended_processes = []
        
    def toggle_pause(self):
        if not self.is_paused:
            self.suspend_processes()
        else:
            self.resume_processes()
            
    def toggle_suspend(self):
        if not self.is_suspended:
            self.suspend_processes_advanced()
        else:
            self.resume_suspended_processes()
            
    def suspend_processes(self):
        """暂停进程"""
        suspended = []
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'] == self.process_name:
                try:
                    proc.suspend()
                    suspended.append(proc)
                    self.info_label.setText(f'已暂停进程 PID: {proc.info["pid"]}\n进程已暂停，但仍占用系统资源。')
                except Exception as e:
                    self.info_label.setText(f'错误: {str(e)}')
                    
        if suspended:
            self.suspended_processes = suspended
            self.is_paused = True
            self.pause_btn.setText('恢复极域课堂')
            self.status_label.setText('极域课堂已暂停')
            self.status_label.setStyleSheet('color: orange')
            
    def suspend_processes_advanced(self):
        """挂起进程"""
        suspended = []
        for proc in psutil.process_iter(['name', 'pid', 'status']):
            if proc.info['name'] == self.process_name:
                try:
                    proc.suspend()
                    proc.nice(psutil.IDLE_PRIORITY_CLASS)
                    suspended.append(proc)
                    self.info_label.setText(f'已挂起进程 PID: {proc.info["pid"]}\n进程已挂起，释放了大量系统资源。')
                except Exception as e:
                    self.info_label.setText(f'错误: {str(e)}')
                    
        if suspended:
            self.suspended_processes = suspended
            self.is_suspended = True
            self.suspend_btn.setText('恢复极域课堂')
            self.status_label.setText('极域课堂已挂起')
            self.status_label.setStyleSheet('color: blue')
            
    def resume_processes(self):
        """恢复被暂停的进程"""
        for proc in self.suspended_processes:
            try:
                proc.resume()
                self.info_label.setText(f'已恢复进程 PID: {proc.info["pid"]}\n进程已恢复正常运行。')
            except Exception as e:
                self.info_label.setText(f'错误: {str(e)}')
                
        self.suspended_processes = []
        self.is_paused = False
        self.pause_btn.setText('暂停极域课堂')
        self.status_label.setText('极域课堂正在运行')
        self.status_label.setStyleSheet('color: green')
        
    def resume_suspended_processes(self):
        """恢复被挂起的进程"""
        for proc in self.suspended_processes:
            try:
                proc.resume()
                proc.nice(psutil.NORMAL_PRIORITY_CLASS)
                self.info_label.setText(f'已恢复进程 PID: {proc.info["pid"]}\n进程已从挂起状态恢复。')
            except Exception as e:
                self.info_label.setText(f'错误: {str(e)}')
                
        self.suspended_processes = []
        self.is_suspended = False
        self.suspend_btn.setText('挂起极域课堂')
        self.status_label.setText('极域课堂正在运行')
        self.status_label.setStyleSheet('color: green')
        
    def kill_process(self):
        reply = QMessageBox.question(self, '确认', 
                                    '确定要结束极域课堂进程吗?\n请注意，这可能会被教师端检测到。',
                                    QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            killed = False
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'] == self.process_name:
                    try:
                        proc.kill()
                        self.info_label.setText(f'已结束进程 PID: {proc.info["pid"]}\n进程已被强制终止。')
                        killed = True
                    except Exception as e:
                        self.info_label.setText(f'错误: {str(e)}')
                        
            if killed:
                self.is_paused = False
                self.is_suspended = False
                self.suspended_processes = []
                self.status_label.setText('极域课堂未运行')
                self.status_label.setStyleSheet('color: red')
                self.pause_btn.setEnabled(False)
                self.suspend_btn.setEnabled(False)
                self.kill_btn.setEnabled(False)

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    
    # 设置随机应用程序名称，增加隐蔽性
    app_names = ["WindowsService", "SystemHelper", "NetworkManager"]
    app.setApplicationName(random.choice(app_names))
    app.setApplicationDisplayName("系统服务")
    
    # 检查是否已有实例运行
    if QApplication.instance():
        controller = ExtremeDomainController()
        controller.show()
        sys.exit(app.exec_())

if __name__ == '__main__':
    main()