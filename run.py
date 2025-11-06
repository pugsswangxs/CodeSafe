import os
import sys
import json
import platform
import subprocess
from pathlib import Path

from PyQt6.QtWidgets import (QApplication, QMainWindow, QTreeWidget, QTreeWidgetItem,
                             QTabWidget, QTextEdit, QToolBar, QComboBox, QPushButton,
                             QFileDialog, QDialog, QTableWidget, QTableWidgetItem,
                             QVBoxLayout, QHBoxLayout, QWidget, QMenu, QMessageBox,
                             QHeaderView, QStyle, QLabel, QSplitter, QCheckBox)
from PyQt6.QtGui import QAction, QFont, QColor, QIcon
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDateTime, QSize

# 获取当前文件的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))
# 获取加密方式文件的路径
temp_setup = os.path.join(current_dir, "password_py.py")


class EncryptThread(QThread):
    """加密线程，用于后台执行加密任务并发送日志信息"""
    log_signal = pyqtSignal(str, str)  # 日志内容，日志级别(INFO/WARNING/ERROR)
    progress_signal = pyqtSignal(int, int)  # 当前进度，总任务数
    finished_signal = pyqtSignal(bool)  # 完成信号，是否成功

    def __init__(self, python_path, file_paths, output_dir=current_dir,rename_enabled = True):
        super().__init__()
        self.python_path = python_path
        self.file_paths = file_paths
        self.output_dir = output_dir
        self.rename_enabled = rename_enabled
        self._is_running = True

    def stop(self):
        """停止加密任务"""
        self._is_running = False
        self.terminate()

    def run(self):
        try:
            total_files = len(self.file_paths)
            success_count = 0

            for index, file_path in enumerate(self.file_paths):
                if not self._is_running:
                    break

                try:
                    # 发送进度信号
                    self.progress_signal.emit(index + 1, total_files)

                    # 输出执行信息
                    current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss")
                    self.log_signal.emit(f"[{current_time}] 开始加密文件 {index + 1}/{total_files}", "INFO")
                    self.log_signal.emit(f"Python解释器: {self.python_path}", "INFO")
                    self.log_signal.emit(f"当前脚本路径: {file_path}", "INFO")

                    # 验证文件存在性
                    if not os.path.exists(file_path):
                        self.log_signal.emit(f"错误: 文件不存在 - {file_path}", "ERROR")
                        continue

                    if not os.path.isfile(file_path):
                        self.log_signal.emit(f"错误: 不是有效的文件 - {file_path}", "ERROR")
                        continue

                    # 确定输出目录
                    if self.output_dir and os.path.isdir(self.output_dir):
                        output_path = self.output_dir
                    else:
                        # 如果没有设置输出目录或目录无效，则使用源文件所在目录
                        output_path = os.path.dirname(current_dir)
                    self.log_signal.emit(f"输出目标路径: {output_path}", "INFO")

                    # 处理路径中的反斜杠问题
                    normalized_file_path = os.path.normpath(file_path).replace(os.sep, '/')
                    normalized_output_path = os.path.normpath(output_path).replace(os.sep, '/')

                    # 构建命令，根据重命名选项添加 -r 参数
                    cmd = f'{self.python_path} "{temp_setup}" -p {normalized_file_path} -o {normalized_output_path}'
                    # 修改为：
                    if self.rename_enabled:
                        cmd += ' -r Y'
                    else:
                        cmd += ' -r N'

                    self.log_signal.emit(f"执行命令: {cmd}", "INFO")

                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore',
                        timeout=300  # 5分钟超时
                    )

                    # 输出执行结果
                    if result.returncode == 0:
                        self.log_signal.emit(f"执行成功: {result.stdout}", "INFO")
                        success_count += 1
                    else:
                        self.log_signal.emit(f"执行失败: {result.stderr}", "ERROR")

                    self.log_signal.emit(f"文件 {os.path.basename(file_path)} 加密完成", "INFO")

                    # 清理临时文件
                    try:
                        build_dir = os.path.join(output_path, "build")
                        if os.path.exists(build_dir) and os.path.isdir(build_dir):
                            import shutil
                            shutil.rmtree(build_dir, ignore_errors=True)
                    except Exception as e:
                        self.log_signal.emit(f"清理临时文件失败: {str(e)}", "WARNING")

                except subprocess.TimeoutExpired:
                    self.log_signal.emit(f"加密超时: {file_path}", "ERROR")
                except Exception as e:
                    self.log_signal.emit(f"处理文件时出错: {str(e)}", "ERROR")

            # 发送完成信号
            if self._is_running:
                self.finished_signal.emit(success_count == total_files)
                self.log_signal.emit(f"加密任务完成: {success_count}/{total_files} 个文件成功",
                                     "INFO" if success_count == total_files else "WARNING")
            else:
                self.log_signal.emit("加密任务被用户终止", "WARNING")

        except Exception as e:
            self.log_signal.emit(f"加密线程崩溃: {str(e)}", "ERROR")
            self.finished_signal.emit(False)


class PythonPathDialog(QDialog):
    """Python路径配置对话框"""

    def __init__(self, current_paths, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置Python路径")
        self.resize(600, 400)
        self.setMinimumSize(500, 300)

        self.paths = current_paths.copy()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        # 说明标签
        info_label = QLabel("请配置可用的Python解释器路径：")
        info_label.setStyleSheet("font-weight: bold; color: #2c3e50;")
        layout.addWidget(info_label)

        # 表格展示路径
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["序号", "路径", "状态"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.add_btn = QPushButton("添加")
        self.edit_btn = QPushButton("修改")
        self.remove_btn = QPushButton("删除")
        self.test_btn = QPushButton("测试选中项")
        self.ok_btn = QPushButton("确定")

        # 设置按钮样式
        for btn in [self.add_btn, self.edit_btn, self.remove_btn, self.test_btn]:
            btn.setMinimumSize(80, 30)
        self.ok_btn.setMinimumSize(100, 35)
        self.ok_btn.setStyleSheet("QPushButton { background-color: #007acc; color: white; font-weight: bold; }")

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.remove_btn)
        btn_layout.addWidget(self.test_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.ok_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

        # 连接信号
        self.add_btn.clicked.connect(self.add_path)
        self.edit_btn.clicked.connect(self.edit_path)
        self.remove_btn.clicked.connect(self.remove_path)
        self.test_btn.clicked.connect(self.test_path)
        self.ok_btn.clicked.connect(self.accept)

        self.refresh_table()

    def refresh_table(self):
        """刷新表格内容"""
        self.table.setRowCount(len(self.paths))
        for i, path in enumerate(self.paths):
            self.table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self.table.setItem(i, 1, QTableWidgetItem(path))

            # 检查路径是否可用
            is_valid = os.path.exists(path) and os.access(path, os.X_OK)
            status_text = "可用" if is_valid else "不可用"
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(QColor("green") if is_valid else QColor("red"))
            self.table.setItem(i, 2, status_item)

    def add_path(self):
        """添加Python路径"""
        filter_str = "可执行文件 (*.exe);;所有文件 (*)" if platform.system() == "Windows" else "可执行文件 (*);;所有文件 (*)"
        path, _ = QFileDialog.getOpenFileName(self, "选择Python解释器", "", filter_str)
        if path:
            if path not in self.paths:
                self.paths.append(path)
                self.refresh_table()
            else:
                QMessageBox.information(self, "提示", "该路径已存在")

    def edit_path(self):
        """修改选中的Python路径"""
        current_row = self.table.currentRow()
        if 0 <= current_row < len(self.paths):
            filter_str = "可执行文件 (*.exe);;所有文件 (*)" if platform.system() == "Windows" else "可执行文件 (*);;所有文件 (*)"
            path, _ = QFileDialog.getOpenFileName(self, "修改Python解释器", self.paths[current_row], filter_str)
            if path:
                self.paths[current_row] = path
                self.refresh_table()

    def remove_path(self):
        """删除选中的Python路径"""
        current_row = self.table.currentRow()
        if 0 <= current_row < len(self.paths):
            reply = QMessageBox.question(self, "确认删除",
                                         f"确定要删除Python路径:\n{self.paths[current_row]}吗？")
            if reply == QMessageBox.StandardButton.Yes:
                del self.paths[current_row]
                self.refresh_table()

    def test_path(self):
        """测试选中的Python路径"""
        current_row = self.table.currentRow()
        if 0 <= current_row < len(self.paths):
            path = self.paths[current_row]
            try:
                result = subprocess.run([path, "--version"],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    QMessageBox.information(self, "测试成功",
                                            f"Python路径有效:\n{path}\n\n版本信息:\n{result.stdout}")
                else:
                    QMessageBox.warning(self, "测试失败",
                                        f"Python路径无效:\n{path}\n\n错误信息:\n{result.stderr}")
            except Exception as e:
                QMessageBox.critical(self, "测试错误", f"测试过程中发生错误:\n{str(e)}")

    def get_paths(self):
        """返回配置的路径"""
        return self.paths


class LogTextEdit(QTextEdit):
    """日志显示组件，支持不同级别日志的颜色显示"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        font = QFont("Consolas", 9)
        self.setFont(font)
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

    def append_log(self, message, level="INFO"):
        """添加日志信息，根据级别显示不同颜色"""
        timestamp = QDateTime.currentDateTime().toString("HH:mm:ss")

        if level == "INFO":
            color = "#000000"  # 黑色
            prefix = "INFO"
        elif level == "WARNING":
            color = "#ff8c00"  # 橙色
            prefix = "WARN"
        elif level == "ERROR":
            color = "#ff0000"  # 红色
            prefix = "ERROR"
        else:
            color = "#666666"  # 灰色
            prefix = "DEBUG"

        # 转义HTML特殊字符
        message = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        formatted_message = f'<span style="color:#666">[{timestamp}]</span> ' \
                            f'<span style="color:{color}; font-weight:bold">[{prefix}]</span> ' \
                            f'<span style="color:{color}">{message}</span>'

        self.append(formatted_message)

        # 自动滚动到底部
        scrollbar = self.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())


class ProgressWidget(QWidget):
    """进度显示组件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 5, 0, 5)

        self.progress_label = QLabel("就绪")
        self.progress_label.setStyleSheet("color: #666; font-size: 11px;")

        layout.addWidget(self.progress_label)
        layout.addStretch()

        self.setLayout(layout)

    def update_progress(self, current, total):
        """更新进度显示"""
        if total > 0:
            percent = (current / total) * 100
            self.progress_label.setText(f"进度: {current}/{total} ({percent:.1f}%)")
            self.progress_label.setStyleSheet("color: #007acc; font-size: 11px; font-weight: bold;")
        else:
            self.progress_label.setText("就绪")
            self.progress_label.setStyleSheet("color: #666; font-size: 11px;")


class PythonFileTree(QTreeWidget):
    """Python文件树组件，用于显示和管理Python文件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.updating_check_state = False  # 防止递归更新的标志
        self.setAcceptDrops(True)  # 启用拖拽功能

        self.init_ui()
        self.root_nodes = []

    def init_ui(self):
        # 设置多列表头
        self.setHeaderLabels(["文件名", "类型", "状态"])
        self.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self.itemExpanded.connect(self.on_item_expanded)
        self.itemChanged.connect(self.on_item_changed)

        # 设置列宽
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

        # 设置样式
        self.setStyleSheet("""
            QTreeWidget {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 3px;
                outline: none;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #f0f0f0;
            }
            QTreeWidget::item:selected {
                background-color: #007acc;
                color: white;
            }
            QTreeWidget::item:hover:!selected {
                background-color: #f0f0f0;
            }
        """)

        self.setAlternatingRowColors(True)
        self.setIconSize(QSize(16, 16))
        self.setIndentation(15)
        self.setAnimated(True)

    def dragEnterEvent(self, event):
        """处理拖拽进入事件"""
        if event.mimeData().hasUrls():
            # 检查拖拽的文件是否包含.py文件或文件夹
            urls = event.mimeData().urls()
            valid = False
            for url in urls:
                file_path = url.toLocalFile()
                if os.path.isfile(file_path) and file_path.endswith('.py'):
                    valid = True
                    break
                elif os.path.isdir(file_path):
                    # 检查文件夹中是否包含.py文件
                    if self.has_python_files(file_path):
                        valid = True
                        break
            if valid:
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        """处理拖拽移动事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        """处理拖拽释放事件"""
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            for url in urls:
                file_path = url.toLocalFile()
                if os.path.isfile(file_path) and file_path.endswith('.py'):
                    # 处理单个.py文件
                    self.add_file_as_root(file_path)
                elif os.path.isdir(file_path):
                    # 处理文件夹
                    self.add_root_folder(file_path)
            event.acceptProposedAction()
        else:
            event.ignore()

    def add_file_as_root(self, file_path):
        """将单个.py文件添加为根节点"""
        if not os.path.isfile(file_path) or not file_path.endswith('.py'):
            return False

        # 检查是否已添加
        for root in self.root_nodes:
            if root.data(0, Qt.ItemDataRole.UserRole) == file_path:
                QMessageBox.information(self, "提示", "该文件已添加")
                return False

        # 创建根节点
        file_name = os.path.basename(file_path)
        root_item = QTreeWidgetItem([file_name, "Python文件", "未选中"])
        root_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
        root_item.setData(0, Qt.ItemDataRole.UserRole, file_path)
        root_item.setData(0, Qt.ItemDataRole.UserRole + 1, True)  # 标记为根节点
        root_item.setCheckState(0, Qt.CheckState.Unchecked)
        root_item.setFlags(root_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

        self.addTopLevelItem(root_item)
        self.root_nodes.append(root_item)
        return True

    def add_root_folder(self, path):
        """添加根文件夹"""
        if not os.path.isdir(path):
            QMessageBox.warning(self, "错误", "选择的路径不是有效的文件夹")
            return False

        # 检查是否已添加
        for root in self.root_nodes:
            if root.data(0, Qt.ItemDataRole.UserRole) == path:
                QMessageBox.information(self, "提示", "该文件夹已添加")
                return False

        # 创建根节点
        root_item = QTreeWidgetItem([os.path.basename(path), "根文件夹", "未选中"])
        root_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
        root_item.setData(0, Qt.ItemDataRole.UserRole, path)
        root_item.setData(0, Qt.ItemDataRole.UserRole + 1, True)  # 标记为根节点
        root_item.setCheckState(0, Qt.CheckState.Unchecked)
        root_item.setFlags(root_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

        # 添加虚拟子节点，用于触发展开事件
        dummy = QTreeWidgetItem(["加载中...", "", ""])
        dummy.setFlags(dummy.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
        root_item.addChild(dummy)

        self.addTopLevelItem(root_item)
        self.root_nodes.append(root_item)
        return True

    def on_item_expanded(self, item):
        """处理节点展开事件"""
        if item.childCount() == 1 and item.child(0).text(0) == "加载中...":
            self.load_children(item)

    def on_item_changed(self, item, column):
        """处理项目状态改变事件"""
        if self.updating_check_state or column != 0:
            return

        self.updating_check_state = True

        try:
            state = item.checkState(0)
            item.setText(2, "已选中" if state == Qt.CheckState.Checked else "未选中")

            # 更新子节点状态
            if item.childCount() > 0:
                self.update_children_state(item, state)

            # 更新父节点状态
            self.update_parent_state(item.parent())

        finally:
            self.updating_check_state = False

    def load_children(self, item):
        """加载子节点"""
        path = item.data(0, Qt.ItemDataRole.UserRole)
        if not path or not os.path.isdir(path):
            return

        # 阻塞信号避免递归
        self.blockSignals(True)

        try:
            # 清除虚拟节点
            item.takeChildren()

            parent_state = item.checkState(0)

            # 加载目录内容
            for entry in os.listdir(path):
                # 过滤掉 __init__.py 文件
                if entry == "__init__.py":
                    continue

                entry_path = os.path.join(path, entry)

                if os.path.isdir(entry_path):
                    has_py_files = self.has_python_files(entry_path)
                    if has_py_files:
                        dir_item = QTreeWidgetItem([entry, "文件夹", "未选中"])
                        dir_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon))
                        dir_item.setData(0, Qt.ItemDataRole.UserRole, entry_path)
                        dir_item.setData(0, Qt.ItemDataRole.UserRole + 1, False)
                        dir_item.setCheckState(0, parent_state)
                        dir_item.setText(2, "已选中" if parent_state == Qt.CheckState.Checked else "未选中")
                        dir_item.setFlags(dir_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)

                        # 添加虚拟子节点
                        dummy = QTreeWidgetItem(["加载中...", "", ""])
                        dummy.setFlags(dummy.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                        dir_item.addChild(dummy)
                        item.addChild(dir_item)

                elif os.path.isfile(entry_path) and entry.endswith(".py"):
                    file_item = QTreeWidgetItem([entry, "Python文件", "未选中"])
                    file_item.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon))
                    file_item.setData(0, Qt.ItemDataRole.UserRole, entry_path)
                    file_item.setData(0, Qt.ItemDataRole.UserRole + 1, False)
                    file_item.setCheckState(0, parent_state)
                    file_item.setText(2, "已选中" if parent_state == Qt.CheckState.Checked else "未选中")
                    file_item.setFlags(file_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.addChild(file_item)

        except PermissionError:
            error_item = QTreeWidgetItem(["权限不足", "错误", ""])
            error_item.setForeground(0, QColor("red"))
            item.addChild(error_item)
        except Exception as e:
            error_item = QTreeWidgetItem([f"加载错误: {str(e)}", "错误", ""])
            error_item.setForeground(0, QColor("red"))
            item.addChild(error_item)
        finally:
            self.blockSignals(False)

    def has_python_files(self, path):
        """检查目录是否包含Python文件"""
        if not os.path.isdir(path):
            return False

        try:
            for entry in os.listdir(path):
                # 过滤掉 __init__.py 文件
                if entry == "__init__.py":
                    continue

                entry_path = os.path.join(path, entry)
                if os.path.isdir(entry_path):
                    if self.has_python_files(entry_path):
                        return True
                elif os.path.isfile(entry_path) and entry.endswith(".py"):
                    return True
        except PermissionError:
            pass

        return False

    def update_children_state(self, parent_item, state):
        """递归更新所有子节点的勾选状态"""
        for i in range(parent_item.childCount()):
            child = parent_item.child(i)
            # 跳过虚拟节点
            if child.text(0) == "加载中...":
                continue

            child.setCheckState(0, state)
            child.setText(2, "已选中" if state == Qt.CheckState.Checked else "未选中")

            # 递归处理子文件夹
            if child.childCount() > 0:
                self.update_children_state(child, state)

    def update_parent_state(self, parent):
        """更新父节点状态"""
        if not parent:
            return

        checked_count = 0
        total_count = 0

        for i in range(parent.childCount()):
            child = parent.child(i)
            # 只统计真实文件节点
            child_path = child.data(0, Qt.ItemDataRole.UserRole)
            if child_path and (child_path.endswith(".py") or os.path.isdir(child_path)):
                total_count += 1
                if child.checkState(0) == Qt.CheckState.Checked:
                    checked_count += 1

        # 更新父节点状态
        if total_count > 0:
            if checked_count == total_count:
                parent.setCheckState(0, Qt.CheckState.Checked)
                parent.setText(2, "已选中")
            elif checked_count == 0:
                parent.setCheckState(0, Qt.CheckState.Unchecked)
                parent.setText(2, "未选中")
            else:
                parent.setCheckState(0, Qt.CheckState.PartiallyChecked)
                parent.setText(2, "部分选中")

        # 递归更新上层节点
        self.update_parent_state(parent.parent())

    def get_selected_files(self):
        """获取所有勾选的Python文件"""
        selected_files = []

        def traverse(item):
            item_path = item.data(0, Qt.ItemDataRole.UserRole)
            if item_path and item_path.endswith(".py"):
                if item.checkState(0) == Qt.CheckState.Checked:
                    selected_files.append(item_path)
            else:
                for i in range(item.childCount()):
                    traverse(item.child(i))

        for i in range(self.topLevelItemCount()):
            traverse(self.topLevelItem(i))

        return selected_files

    def show_context_menu(self, position):
        """显示右键菜单"""
        try:
            item = self.itemAt(position)
            if not item:
                return

            menu = QMenu()
            path = item.data(0, Qt.ItemDataRole.UserRole)
            is_root = item.data(0, Qt.ItemDataRole.UserRole + 1)

            if is_root:
                # 根节点菜单
                close_action = QAction("关闭根文件夹", self)
                close_action.triggered.connect(lambda: self.remove_root(item))
                reload_action = QAction("重新加载", self)
                reload_action.triggered.connect(lambda: self.reload_root(item))
                open_action = QAction("在文件管理器中打开", self)
                open_action.triggered.connect(lambda: self.open_in_file_manager(item))

                menu.addAction(close_action)
                menu.addAction(reload_action)
                menu.addAction(open_action)
            else:
                # 文件/文件夹菜单
                if path and path.endswith(".py"):
                    encrypt_action = QAction("加密此文件", self)
                    encrypt_action.triggered.connect(lambda: self.encrypt_selected(item))
                    menu.addAction(encrypt_action)

                open_action = QAction("在文件管理器中打开", self)
                open_action.triggered.connect(lambda: self.open_in_file_manager(item))
                menu.addAction(open_action)

            menu.exec(self.viewport().mapToGlobal(position))
        except Exception as e:
            QMessageBox.critical(self, "菜单错误", f"右键菜单出错: {str(e)}")

    def remove_root(self, item):
        """移除根节点"""
        if item in self.root_nodes:
            self.root_nodes.remove(item)
            index = self.indexOfTopLevelItem(item)
            self.takeTopLevelItem(index)

    def reload_root(self, item):
        """重新加载根节点"""
        item.takeChildren()
        dummy = QTreeWidgetItem(["加载中..."])
        dummy.setFlags(dummy.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
        item.addChild(dummy)
        self.load_children(item)

    def open_in_file_manager(self, item):
        """在文件管理器中打开路径"""
        try:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            # 将path 根据不同的系统来设置不同的样式
            if platform.system() == "Windows":
                path = path.replace("/", "\\")
            else:
                path = path.replace("\\", "/")

            if not path or not os.path.exists(path):
                QMessageBox.warning(self, "错误", "路径不存在或无效")
                return

            # 确保打开的是文件所在的文件夹
            if os.path.isfile(path):
                folder_path = os.path.dirname(path)
            else:
                folder_path = path

            if platform.system() == "Windows":
                # Windows下打开文件夹并选中文件
                subprocess.run(["explorer", folder_path])
            elif platform.system() == "Linux":
                subprocess.run(["xdg-open", folder_path])
            elif platform.system() == "Darwin":
                subprocess.run(["open", folder_path], )
        except Exception as e:
            QMessageBox.warning(self, "错误", f"无法打开文件管理器: {str(e)}")

    def encrypt_selected(self, item):
        """加密选中项"""
        try:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            if not path:
                QMessageBox.warning(self, "错误", "无效的文件路径")
                return

            if os.path.isfile(path) and path.endswith(".py"):
                if self.parent:
                    self.parent.encrypt_files([path])
            else:
                QMessageBox.warning(self, "错误", "只能加密Python文件")
        except Exception as e:
            QMessageBox.critical(self, "加密错误", f"准备加密时出错: {str(e)}")


class PythonPackager(QMainWindow):
    """主窗口类"""

    def __init__(self):
        super().__init__()
        self.config_file = "config.json"
        self.python_paths = []
        self.output_dir = current_dir
        self.last_selected_index = 0
        self.encrypt_thread = None
        self.open_folder_after_completion = False  # 新增属性
        self.icon_path = Path(current_dir) / "resources" / "icons"
        self.icons = {}

        self.load_icons()
        self.init_ui()
        self.load_config()

    def load_icons(self):
        """加载图标"""
        icon_files = {
            "settings": "settings.svg",
            "folder": "folder-heart.svg",
            "run": "play-circle.svg",
            "clear": "delete_all.svg",
            "delete": "delete.svg",
            "stop": "stop-circle.svg",
            "folder_item": "folder_special-copy.svg",
            "python_file": "file-code.svg",
        }

        # 尝试加载自定义图标
        for key, filename in icon_files.items():
            try:
                icon_path = self.icon_path / filename
                if icon_path.exists():
                    self.icons[key] = QIcon(str(icon_path))
                else:
                    self.icons[key] = self._get_default_icon(key)
            except Exception:
                self.icons[key] = self._get_default_icon(key)

    def _get_default_icon(self, icon_type):
        """获取默认系统图标"""
        icon_map = {
            "settings": QStyle.StandardPixmap.SP_ComputerIcon,
            "folder": QStyle.StandardPixmap.SP_DirIcon,
            "run": QStyle.StandardPixmap.SP_MediaPlay,
            "clear": QStyle.StandardPixmap.SP_DialogResetButton,
            "delete": QStyle.StandardPixmap.SP_TrashIcon,
            "stop": QStyle.StandardPixmap.SP_MediaStop,
            "folder_item": QStyle.StandardPixmap.SP_DirIcon,
            "python_file": QStyle.StandardPixmap.SP_FileIcon,
        }
        return self.style().standardIcon(icon_map.get(icon_type, QStyle.StandardPixmap.SP_FileIcon))

    def init_ui(self):
        """初始化界面"""
        self.setWindowTitle("Python代码打包工具")
        self.resize(1200, 800)
        self.setMinimumSize(800, 600)

        # 创建中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # 创建工具栏
        self.create_toolbar()

        # 创建分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        # 左侧文件树
        self.file_tree = PythonFileTree(self)
        self.file_tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        splitter.addWidget(self.file_tree)

        # 右侧日志标签页
        self.log_tabs = QTabWidget()
        self.log_tabs.setDocumentMode(True)

        self.main_log = LogTextEdit()
        self.log_tabs.addTab(self.main_log, "主日志")

        splitter.addWidget(self.log_tabs)
        splitter.setSizes([400, 800])

        main_layout.addWidget(splitter)

        # 底部状态栏
        self.create_status_bar()

    def create_toolbar(self):
        """创建工具栏"""
        toolbar = QToolBar("主工具栏")
        toolbar.setIconSize(QSize(20, 20))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Python路径选择
        toolbar.addWidget(QLabel("Python解释器:"))
        self.python_combo = QComboBox()
        self.python_combo.setMinimumWidth(250)
        self.python_combo.setToolTip("选择用于加密的Python解释器")
        toolbar.addWidget(self.python_combo)

        # 设置Python路径按钮
        settings_action = QAction(self.icons["settings"], "设置Python路径", self)
        settings_action.triggered.connect(self.show_python_path_dialog)
        settings_action.setToolTip("配置Python解释器路径")
        toolbar.addAction(settings_action)

        toolbar.addSeparator()

        # 浏览文件夹按钮
        browse_action = QAction(self.icons["folder"], "添加文件夹", self)
        browse_action.triggered.connect(self.browse_folder)
        browse_action.setToolTip("添加包含Python文件的文件夹")
        toolbar.addAction(browse_action)

        toolbar.addSeparator()

        # 批量执行按钮
        execute_action = QAction(self.icons["run"], "批量加密", self)
        execute_action.triggered.connect(self.batch_encrypt)
        execute_action.setToolTip("加密所有选中的Python文件")
        toolbar.addAction(execute_action)

        # 停止任务按钮
        self.stop_action = QAction(self.icons["stop"], "停止任务", self)
        self.stop_action.triggered.connect(self.stop_current_task)
        self.stop_action.setEnabled(False)
        self.stop_action.setToolTip("停止当前加密任务")
        toolbar.addAction(self.stop_action)

        toolbar.addSeparator()

        # 清除日志按钮
        clear_log_action = QAction(self.icons["clear"], "清除当前日志", self)
        clear_log_action.triggered.connect(self.clear_current_log)
        clear_log_action.setToolTip("清除当前标签页的日志")
        toolbar.addAction(clear_log_action)

        # 添加新按钮：删除所有非主日志标签页
        remove_extra_tabs_action = QAction(self.icons["delete"], "删除额外日志页", self)
        remove_extra_tabs_action.triggered.connect(self.remove_extra_log_tabs)
        remove_extra_tabs_action.setToolTip("删除所有非主日志的标签页")
        toolbar.addAction(remove_extra_tabs_action)

        toolbar.addSeparator()

        # 输出路径相关控件
        output_action = QAction("设置输出路径", self)
        output_action.triggered.connect(self.select_output_dir)
        output_action.setToolTip("设置加密文件的输出目录")
        toolbar.addAction(output_action)

        # 默认输出路径按钮
        self.default_output_btn = QPushButton("默认输出路径")
        self.default_output_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 3px;
                padding: 2px 5px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.default_output_btn.clicked.connect(self.set_default_output_path)
        self.default_output_btn.setToolTip("点击设置为默认输出路径（与源文件同目录）")
        toolbar.addWidget(self.default_output_btn)

        toolbar.addSeparator()

        # 重命名单选框
        self.rename_checkbox = QCheckBox("重命名文件")
        self.rename_checkbox.setChecked(True)  # 默认选中
        self.rename_checkbox.setToolTip("选中时会对生成的文件进行重命名")
        toolbar.addWidget(self.rename_checkbox)

        # 添加"完成后打开文件夹"复选框
        self.open_folder_checkbox = QCheckBox("完成后打开文件夹")
        self.open_folder_checkbox.setChecked(self.open_folder_after_completion)
        self.open_folder_checkbox.setToolTip("加密完成后自动打开输出文件夹")
        self.open_folder_checkbox.stateChanged.connect(self.on_open_folder_checkbox_changed)
        toolbar.addWidget(self.open_folder_checkbox)

    # 添加处理复选框状态改变的方法
    def on_open_folder_checkbox_changed(self, state):
        """处理'完成后打开文件夹'复选框状态改变"""
        self.open_folder_after_completion = (state == Qt.CheckState.Checked.value)
        self.save_config()

    # 添加打开输出文件夹的方法
    def open_output_folder(self):
        """打开输出文件夹"""
        try:
            if not self.output_dir or not os.path.exists(self.output_dir):
                QMessageBox.warning(self, "警告", "输出目录不存在")
                return

            if platform.system() == "Windows":
                subprocess.run(["explorer", self.output_dir])
            elif platform.system() == "Linux":
                subprocess.run(["xdg-open", self.output_dir])
            elif platform.system() == "Darwin":
                subprocess.run(["open", self.output_dir])

            self.main_log.append_log(f"已打开输出文件夹: {self.output_dir}", "INFO")
        except Exception as e:
            self.main_log.append_log(f"打开输出文件夹失败: {str(e)}", "ERROR")

    # 在 PythonPackager 类中添加新方法
    def remove_extra_log_tabs(self):
        """删除所有非主日志的标签页"""
        try:
            # 从最后一个标签页开始删除，避免索引变化问题
            for i in range(self.log_tabs.count() - 1, -1, -1):
                widget = self.log_tabs.widget(i)
                tab_text = self.log_tabs.tabText(i)

                # 保留主日志标签页，删除其他所有标签页
                if tab_text != "主日志" and widget != self.main_log:
                    self.log_tabs.removeTab(i)

            self.main_log.append_log("已删除所有额外的日志标签页", "INFO")
        except Exception as e:
            self.main_log.append_log(f"删除日志标签页时出错: {str(e)}", "ERROR")

    def create_status_bar(self):
        """创建状态栏"""
        self.status_bar = self.statusBar()

        # 进度显示
        self.progress_widget = ProgressWidget()
        self.status_bar.addPermanentWidget(self.progress_widget)

        # 输出路径显示
        self.output_path_label = QLabel("当前输出到默认路径")
        self.output_path_label.setStyleSheet("color: #666; font-size: 11px; margin-left: 10px;")
        self.status_bar.addPermanentWidget(self.output_path_label)

        # 初始状态
        self.update_task_status(False)
        self.update_output_path_display()

        # 默认输出路径按钮
        self.default_output_btn = QPushButton("默认输出路径")
        self.default_output_btn.setStyleSheet("""
            QPushButton {
                background-color: #f0f0f0;
                border: 1px solid #ccc;
                border-radius: 3px;
                padding: 2px 5px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
        """)
        self.default_output_btn.clicked.connect(self.set_default_output_path)
        self.default_output_btn.setToolTip("点击设置为默认输出路径（与源文件同目录）")
        self.status_bar.addPermanentWidget(self.default_output_btn)

        # 初始状态
        self.update_task_status(False)
        self.update_output_path_display()

    def update_output_path_display(self):
        """更新输出路径显示"""
        current_working_dir = os.getcwd()
        if self.output_dir and os.path.isdir(self.output_dir):
            # 检查是否设置为当前工作目录
            if os.path.normpath(self.output_dir) == os.path.normpath(current_working_dir):
                self.output_path_label.setText("当前输出到当前工作目录")
                self.output_path_label.setStyleSheet(
                    "color: #007acc; font-size: 11px; font-weight: bold; margin-left: 10px;")
            else:
                display_path = self.output_dir
                # 如果路径过长，进行截断处理
                if len(display_path) > 50:
                    display_path = "..." + display_path[-47:]
                self.output_path_label.setText(f"当前输出路径: {display_path}")
                self.output_path_label.setStyleSheet(
                    "color: #007acc; font-size: 11px; font-weight: bold; margin-left: 10px;")
        else:
            self.output_path_label.setText("当前输出到源文件目录")
            self.output_path_label.setStyleSheet("color: #666; font-size: 11px; margin-left: 10px;")

    def clear_current_log(self):
        """清除当前日志标签页的内容"""
        current_widget = self.log_tabs.currentWidget()
        if current_widget and isinstance(current_widget, LogTextEdit):
            current_widget.clear()
            self.main_log.append_log("已清除当前日志", "INFO")

    def stop_current_task(self):
        """停止当前正在执行的任务"""
        if self.encrypt_thread and self.encrypt_thread.isRunning():
            reply = QMessageBox.question(self, "确认停止",
                                         "确定要停止当前加密任务吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.encrypt_thread.stop()
                self.main_log.append_log("用户请求停止加密任务", "WARNING")
                self.update_task_status(False)

    def update_task_status(self, is_running):
        """更新任务执行状态显示"""
        if is_running:
            self.status_bar.showMessage("正在执行加密任务...")
            self.stop_action.setEnabled(True)
        else:
            self.status_bar.showMessage("就绪")
            self.stop_action.setEnabled(False)

    def select_output_dir(self):
        """选择输出目录"""
        directory = QFileDialog.getExistingDirectory(self, "选择输出目录", "")
        if directory:
            self.output_dir = directory
            self.main_log.append_log(f"输出目录设置为: {directory}", "INFO")
            self.update_output_path_display()

    def set_default_output_path(self):
        """设置为当前代码执行的地方"""
        # 获取当前工作目录作为默认输出路径
        self.output_dir = os.getcwd()
        self.main_log.append_log(f"输出目录已设置为当前工作目录: {self.output_dir}", "INFO")
        self.update_output_path_display()
        self.save_config()

    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    self.python_paths = config.get("python_paths", [])
                    self.last_selected_index = config.get("last_selected_index", 0)
                    self.output_dir = config.get("output_dir") if config.get(
                        "output_dir") is not None else current_dir
                    # 加载新配置项
                    self.open_folder_after_completion = config.get("open_folder_after_completion", False)

                    # 更新下拉框
                    self.python_combo.clear()
                    self.python_combo.addItems(self.python_paths)

                    # 设置上次选择的路径
                    if 0 <= self.last_selected_index < len(self.python_paths):
                        self.python_combo.setCurrentIndex(self.last_selected_index)

                    # 更新复选框状态
                    if hasattr(self, 'open_folder_checkbox'):
                        self.open_folder_checkbox.setChecked(self.open_folder_after_completion)

            self.main_log.append_log("配置加载完成", "INFO")
            self.update_output_path_display()
        except Exception as e:
            self.main_log.append_log(f"加载配置文件失败: {str(e)}", "ERROR")

    # 更新 save_config 方法
    def save_config(self):
        """保存配置文件"""
        try:
            config = {
                "python_paths": self.python_paths,
                "last_selected_index": self.python_combo.currentIndex(),
                "output_dir": self.output_dir,
                "open_folder_after_completion": self.open_folder_after_completion  # 保存新配置项
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.main_log.append_log(f"保存配置文件失败: {str(e)}", "ERROR")

    def show_python_path_dialog(self):
        """显示Python路径配置对话框"""
        dialog = PythonPathDialog(self.python_paths, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.python_paths = dialog.get_paths()
            self.python_combo.clear()
            self.python_combo.addItems(self.python_paths)
            self.save_config()
            self.main_log.append_log("Python路径配置已更新", "INFO")

    def browse_folder(self):
        """浏览并添加文件夹"""
        folder = QFileDialog.getExistingDirectory(self, "选择包含Python文件的文件夹")
        if folder:
            if self.file_tree.add_root_folder(folder):
                self.main_log.append_log(f"成功添加文件夹: {folder}", "INFO")
            else:
                self.main_log.append_log(f"文件夹添加失败或已存在: {folder}", "WARNING")

    def get_current_python_path(self):
        """获取当前选择的Python路径"""
        if self.python_combo.currentIndex() >= 0 and self.python_paths:
            return self.python_paths[self.python_combo.currentIndex()]
        return None

    def batch_encrypt(self):
        """批量加密选中的文件"""
        try:
            python_path = self.get_current_python_path()
            if not python_path:
                QMessageBox.warning(self, "警告", "请先设置Python解释器路径")
                return

            if not os.path.exists(python_path) or not os.access(python_path, os.X_OK):
                QMessageBox.warning(self, "警告", f"Python解释器无效或没有执行权限: {python_path}")
                return

            selected_files = self.file_tree.get_selected_files()
            if not selected_files:
                QMessageBox.information(self, "提示", "请先选择要加密的Python文件")
                return

            self.encrypt_files(selected_files)

        except Exception as e:
            QMessageBox.critical(self, "批量加密错误", f"批量加密时出错: {str(e)}")
            self.main_log.append_log(f"批量加密错误: {str(e)}", "ERROR")

    def encrypt_files(self, file_paths):
        """加密指定的文件列表"""
        try:
            python_path = self.get_current_python_path()
            if not python_path:
                QMessageBox.warning(self, "警告", "请先设置Python解释器路径")
                return

            # 检查Python路径有效性
            if not os.path.exists(python_path):
                QMessageBox.warning(self, "警告", f"Python解释器不存在: {python_path}")
                return

            if not os.access(python_path, os.X_OK):
                QMessageBox.warning(self, "警告", f"Python解释器没有执行权限: {python_path}")
                return

            # 检查是否有任务正在执行
            if self.encrypt_thread and self.encrypt_thread.isRunning():
                QMessageBox.warning(self, "警告", "已有任务正在执行，请等待完成或停止当前任务")
                return

            # 创建新的日志标签
            timestamp = QDateTime.currentDateTime().toString("HHmmss")
            log_widget = LogTextEdit()
            self.log_tabs.addTab(log_widget, f"任务{timestamp}")
            self.log_tabs.setCurrentWidget(log_widget)

            # 启动加密线程时传递重命名选项
            rename_enabled = self.rename_checkbox.isChecked() if hasattr(self, 'rename_checkbox') else True
            self.encrypt_thread = EncryptThread(python_path, file_paths, self.output_dir, rename_enabled)
            self.encrypt_thread.log_signal.connect(log_widget.append_log)
            self.encrypt_thread.log_signal.connect(self.main_log.append_log)
            self.encrypt_thread.progress_signal.connect(self.progress_widget.update_progress)
            self.encrypt_thread.finished_signal.connect(self.on_encrypt_finished)



            self.update_task_status(True)
            self.encrypt_thread.start()

            self.main_log.append_log(f"开始加密 {len(file_paths)} 个文件", "INFO")

        except Exception as e:
            QMessageBox.critical(self, "加密错误", f"启动加密时出错: {str(e)}")
            self.main_log.append_log(f"启动加密失败: {str(e)}", "ERROR")
            self.update_task_status(False)

    # 修改 on_encrypt_finished 方法（替换现有的 on_encrypt_finished 方法）
    def on_encrypt_finished(self, success):
        """加密完成回调"""
        self.update_task_status(False)
        self.progress_widget.update_progress(0, 0)

        if success:
            self.main_log.append_log("所有文件加密完成", "INFO")
        else:
            self.main_log.append_log("加密任务完成，但有部分文件失败", "WARNING")

        # 如果勾选了"完成后打开文件夹"，则打开输出文件夹
        if self.open_folder_after_completion:
            self.open_output_folder()

    def on_item_double_clicked(self, item, column):
        """双击文件节点事件处理"""
        try:
            path = item.data(0, Qt.ItemDataRole.UserRole)
            if path and os.path.isfile(path) and path.endswith(".py"):
                self.encrypt_files([path])
        except Exception as e:
            QMessageBox.critical(self, "双击操作错误", f"双击文件时出错: {str(e)}")

    def closeEvent(self, event):
        """关闭事件处理"""
        # 停止运行中的任务
        if self.encrypt_thread and self.encrypt_thread.isRunning():
            reply = QMessageBox.question(self, "确认退出",
                                         "有任务正在运行，确定要退出吗？",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.encrypt_thread.stop()
                self.encrypt_thread.wait(2000)  # 等待2秒
                event.accept()
            else:
                event.ignore()
        else:
            self.save_config()
            event.accept()


if __name__ == "__main__":
    # 全局异常捕获
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        error_msg = f"未处理的异常:\n类型: {exc_type.__name__}\n错误: {exc_value}"
        print(error_msg, file=sys.stderr)

        # 如果GUI已启动，显示错误对话框
        app = QApplication.instance()
        if app is not None:
            QMessageBox.critical(None, "程序错误", error_msg)


    sys.excepthook = handle_exception

    # 启用高DPI缩放
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("Python代码打包工具")
    app.setApplicationVersion("2.0.0")

    # 设置应用程序字体
    font = QFont("Microsoft YaHei", 9)
    app.setFont(font)

    window = PythonPackager()
    window.show()

    sys.exit(app.exec())