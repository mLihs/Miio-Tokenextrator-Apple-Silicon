from __future__ import annotations

import csv
import json
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from PySide6.QtCore import QObject, QRunnable, Qt, QSettings, QThreadPool, Signal, Slot
from PySide6.QtGui import QAction, QKeySequence, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:  # pragma: no cover - runtime fallback for bundled execution
    from .bridge import InteractionCallbacks
    from .service import AuthenticationError, TokenExtractorService
except ImportError:
    from token_extractor_gui.bridge import InteractionCallbacks
    from token_extractor_gui.service import AuthenticationError, TokenExtractorService

ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def get_user_friendly_error(exception: Exception) -> str:
    """Convert technical exceptions to user-friendly error messages."""
    error_str = str(exception).lower()
    
    if "connection" in error_str or "network" in error_str:
        return (
            "Network Connection Error\n\n"
            "Could not connect to Xiaomi Cloud servers.\n\n"
            "Please check:\n"
            "• Your internet connection is active\n"
            "• Firewall is not blocking the application\n"
            "• VPN or proxy settings if applicable"
        )
    elif "timeout" in error_str:
        return (
            "Request Timeout\n\n"
            "The server took too long to respond.\n\n"
            "Please try again. If the problem persists:\n"
            "• Check your internet speed\n"
            "• Try a different server region"
        )
    elif "authentication" in error_str or "login" in error_str or "password" in error_str:
        return (
            "Authentication Failed\n\n"
            "Could not log in with the provided credentials.\n\n"
            "Please verify:\n"
            "• Username and password are correct\n"
            "• Account is a Xiaomi Cloud account (not Roborock or other brands)\n"
            "• Two-factor authentication code is valid"
        )
    elif "captcha" in error_str:
        return (
            "CAPTCHA Verification Failed\n\n"
            "The CAPTCHA solution was incorrect.\n\n"
            "Please try again and enter the CAPTCHA carefully."
        )
    elif "qr" in error_str or "scan" in error_str:
        return (
            "QR Code Login Failed\n\n"
            "The QR code was not scanned or expired.\n\n"
            "Please:\n"
            "• Scan the QR code with your Xiaomi Home app\n"
            "• Make sure you're using the correct Xiaomi account\n"
            "• Try generating a new QR code"
        )
    elif "token" in error_str and "service" in error_str:
        return (
            "Session Token Error\n\n"
            "Failed to obtain authentication token.\n\n"
            "This is usually temporary. Please:\n"
            "• Wait a few minutes and try again\n"
            "• Restart the application\n"
            "• Try using QR code login instead"
        )
    else:
        # Generic error with the actual exception message
        return (
            f"An Error Occurred\n\n"
            f"{str(exception)}\n\n"
            f"If this problem persists, please try:\n"
            f"• Restarting the application\n"
            f"• Checking your internet connection\n"
            f"• Using a different server region"
        )


class ResponseFuture:
    def __init__(self) -> None:
        self._event = threading.Event()
        self._value: Optional[str] = None

    def set_result(self, value: Optional[str]) -> None:
        self._value = value
        self._event.set()

    def wait(self) -> Optional[str]:
        self._event.wait()
        return self._value


class WorkerSignals(QObject):
    log = Signal(str)
    finished = Signal(object)
    error = Signal(str)
    captcha = Signal(bytes, str, object)
    twofactor = Signal(str, object)
    qr = Signal(bytes, str, str)


@dataclass
class WorkerConfig:
    mode: str
    username: Optional[str] = None
    password: Optional[str] = None
    servers: Optional[List[str]] = None
    include_ble_keys: bool = True


class TokenExtractorWorker(QRunnable):
    def __init__(self, config: WorkerConfig) -> None:
        super().__init__()
        self.config = config
        self.signals = WorkerSignals()

    def _log(self, message: str) -> None:
        self.signals.log.emit(message)

    def _request_captcha(self, image_bytes: bytes, url: str) -> Optional[str]:
        future = ResponseFuture()
        self.signals.captcha.emit(image_bytes, url, future)
        return future.wait()

    def _request_twofactor(self, prompt: str) -> Optional[str]:
        future = ResponseFuture()
        self.signals.twofactor.emit(prompt, future)
        return future.wait()

    def _display_qr(self, image_bytes: bytes, login_url: str, image_url: str) -> None:
        self.signals.qr.emit(image_bytes, login_url, image_url)

    def run(self) -> None:
        callbacks = InteractionCallbacks(
            log=self._log,
            request_captcha=self._request_captcha,
            request_twofactor=self._request_twofactor,
            display_qr=self._display_qr,
        )
        try:
            service = TokenExtractorService(callbacks, include_ble_keys=self.config.include_ble_keys)
            servers = self.config.servers
            if self.config.mode == "password":
                if not self.config.username or not self.config.password:
                    raise ValueError("Username and password are required.")
                service.authenticate_with_password(self.config.username, self.config.password)
            elif self.config.mode == "qr":
                service.authenticate_with_qr()
            else:
                raise ValueError(f"Unsupported mode {self.config.mode}")
            data = service.fetch_devices(servers=servers)
            self.signals.finished.emit(data)
        except AuthenticationError as exc:
            self.signals.error.emit(get_user_friendly_error(exc))
        except ConnectionError as exc:
            self.signals.error.emit(get_user_friendly_error(exc))
        except Exception as exc:  # pragma: no cover - defensive logging
            self.signals.error.emit(get_user_friendly_error(exc))


class CaptchaDialog(QDialog):
    def __init__(self, image_bytes: bytes, image_url: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Captcha Verification")
        layout = QVBoxLayout(self)

        pixmap = QPixmap()
        pixmap.loadFromData(image_bytes)

        image_label = QLabel()
        image_label.setAlignment(Qt.AlignCenter)
        image_label.setPixmap(pixmap)
        image_label.setMinimumSize(320, 200)
        image_label.setScaledContents(True)
        layout.addWidget(image_label)

        layout.addWidget(QLabel(f"Image URL: {image_url}"))

        self._input = QLineEdit()
        self._input.setPlaceholderText("Enter captcha (case-sensitive)")
        layout.addWidget(self._input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def code(self) -> str:
        return self._input.text().strip()


class TwoFactorDialog(QDialog):
    def __init__(self, prompt: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Two-Factor Authentication")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(prompt))
        self._input = QLineEdit()
        self._input.setPlaceholderText("Enter verification code")
        layout.addWidget(self._input)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def code(self) -> str:
        return self._input.text().strip()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Xiaomi Cloud Token Extractor")
        self.resize(1024, 720)
        self.pool = QThreadPool.globalInstance()
        self._current_worker: Optional[TokenExtractorWorker] = None
        self._device_data: Optional[List[Dict[str, Any]]] = None
        self._build_ui()
        
        # Add keyboard shortcut for copy
        copy_action = QAction("Copy", self)
        copy_action.setShortcut(QKeySequence.Copy)
        copy_action.triggered.connect(self._copy_selected_items)
        self.addAction(copy_action)
        
        # Restore settings from previous session
        self.restore_settings()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        self.tabs = QTabWidget()
        self._build_password_tab()
        self._build_qr_tab()
        root_layout.addWidget(self.tabs)

        # Search/Filter section
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter devices by name, IP, token, MAC, or model...")
        self.search_input.textChanged.connect(self._filter_devices)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        root_layout.addLayout(search_layout)

        self.splitter = QSplitter(Qt.Vertical)

        self.device_tree = QTreeWidget()
        self.device_tree.setColumnCount(7)
        self.device_tree.setHeaderLabels(["Name", "Device ID", "Token", "IP", "MAC", "Model", "BLE Key"])
        self.device_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.device_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.device_tree.customContextMenuRequested.connect(self._show_context_menu)
        
        # Configure column auto-resize and sorting
        self.device_tree.setSortingEnabled(True)
        header = self.device_tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        
        self.splitter.addWidget(self.device_tree)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.splitter.addWidget(self.log_view)
        self.splitter.setSizes([500, 200])

        root_layout.addWidget(self.splitter)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Fetching devices... %p%")
        root_layout.addWidget(self.progress_bar)

        # Export buttons
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        
        self.export_json_button = QPushButton("Export to JSON")
        self.export_json_button.clicked.connect(self._on_export_json)
        self.export_json_button.setEnabled(False)
        export_layout.addWidget(self.export_json_button)
        
        self.export_yaml_button = QPushButton("Export to YAML")
        self.export_yaml_button.clicked.connect(self._on_export_yaml)
        self.export_yaml_button.setEnabled(False)
        export_layout.addWidget(self.export_yaml_button)
        
        self.export_csv_button = QPushButton("Export to CSV")
        self.export_csv_button.clicked.connect(self._on_export_csv)
        self.export_csv_button.setEnabled(False)
        export_layout.addWidget(self.export_csv_button)
        
        root_layout.addLayout(export_layout)

    def _build_password_tab(self) -> None:
        tab = QWidget()
        layout = QFormLayout(tab)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Xiaomi account email/phone/user ID")
        layout.addRow("Username", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addRow("Password", self.password_input)

        self.password_server_combo = self._make_server_combo()
        layout.addRow("Server", self.password_server_combo)

        self.include_ble_checkbox = QCheckBox("Include BLE encryption keys")
        self.include_ble_checkbox.setChecked(True)
        layout.addRow("", self.include_ble_checkbox)

        self.fetch_password_button = QPushButton("Fetch devices")
        self.fetch_password_button.clicked.connect(self._on_fetch_password)
        layout.addRow("", self.fetch_password_button)

        self.tabs.addTab(tab, "Password login")

    def _build_qr_tab(self) -> None:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form_row = QFormLayout()
        self.qr_server_combo = self._make_server_combo()
        form_row.addRow("Server", self.qr_server_combo)

        layout.addLayout(form_row)

        self.qr_label = QLabel("QR code will appear here after requesting devices.")
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumHeight(320)
        self.qr_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.qr_label)

        self.fetch_qr_button = QPushButton("Fetch devices via QR login")
        self.fetch_qr_button.clicked.connect(self._on_fetch_qr)
        layout.addWidget(self.fetch_qr_button)

        self.tabs.addTab(tab, "QR login")

    def _make_server_combo(self) -> QComboBox:
        combo = QComboBox()
        combo.addItem("All regions", None)
        for server in TokenExtractorService.available_servers():
            combo.addItem(server.upper(), server)
        return combo

    def _selected_servers(self, combo: QComboBox) -> List[str]:
        data = combo.currentData()
        if data:
            return [data]
        return TokenExtractorService.available_servers()

    @Slot()
    def _on_fetch_password(self) -> None:
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, "Missing credentials", "Please provide both username and password.")
            return
        servers = self._selected_servers(self.password_server_combo)
        include_ble = self.include_ble_checkbox.isChecked()
        config = WorkerConfig(
            mode="password",
            username=username,
            password=password,
            servers=servers,
            include_ble_keys=include_ble,
        )
        self._start_worker(config)

    @Slot()
    def _on_fetch_qr(self) -> None:
        servers = self._selected_servers(self.qr_server_combo)
        include_ble = self.include_ble_checkbox.isChecked()
        config = WorkerConfig(mode="qr", servers=servers, include_ble_keys=include_ble)
        self._start_worker(config)

    def _start_worker(self, config: WorkerConfig) -> None:
        self._set_busy(True)
        self.log_view.appendPlainText("Starting extraction...")
        self.device_tree.clear()
        self._current_worker = TokenExtractorWorker(config)
        worker = self._current_worker
        worker.signals.log.connect(self._append_log)
        worker.signals.error.connect(self._handle_error)
        worker.signals.finished.connect(self._handle_finished)
        worker.signals.captcha.connect(self._handle_captcha)
        worker.signals.twofactor.connect(self._handle_twofactor)
        worker.signals.qr.connect(self._handle_qr_image)
        self.pool.start(worker)

    def _set_busy(self, busy: bool) -> None:
        self.fetch_password_button.setDisabled(busy)
        self.fetch_qr_button.setDisabled(busy)
        has_devices = self.device_tree.topLevelItemCount() > 0
        self.export_csv_button.setDisabled(busy or not has_devices)
        self.export_json_button.setDisabled(busy or not has_devices)
        self.export_yaml_button.setDisabled(busy or not has_devices)
        self.progress_bar.setVisible(busy)
        if busy:
            self.progress_bar.setRange(0, 0)  # Indeterminate progress
        QApplication.setOverrideCursor(Qt.WaitCursor if busy else Qt.ArrowCursor)

    @Slot(str)
    def _append_log(self, message: str) -> None:
        clean = ANSI_ESCAPE_RE.sub("", message)
        if clean:
            self.log_view.appendPlainText(clean)

    @Slot(object)
    def _handle_finished(self, data) -> None:
        self._set_busy(False)
        self._device_data = data
        self._populate_devices(data)
        self.log_view.appendPlainText("Extraction completed.")
        has_devices = self.device_tree.topLevelItemCount() > 0
        self.export_csv_button.setEnabled(has_devices)
        self.export_json_button.setEnabled(has_devices)
        self.export_yaml_button.setEnabled(has_devices)
        QApplication.restoreOverrideCursor()

    @Slot(str)
    def _handle_error(self, message: str) -> None:
        self._set_busy(False)
        self.export_csv_button.setEnabled(False)
        self.export_json_button.setEnabled(False)
        self.export_yaml_button.setEnabled(False)
        QApplication.restoreOverrideCursor()
        QMessageBox.critical(self, "Error", message)

    @Slot(bytes, str, object)
    def _handle_captcha(self, image_bytes: bytes, image_url: str, future: ResponseFuture) -> None:
        try:
            dialog = CaptchaDialog(image_bytes, image_url, self)
            if dialog.exec() == QDialog.Accepted:
                future.set_result(dialog.code())
            else:
                future.set_result(None)
        except Exception:
            future.set_result(None)

    @Slot(str, object)
    def _handle_twofactor(self, prompt: str, future: ResponseFuture) -> None:
        try:
            dialog = TwoFactorDialog(prompt, self)
            if dialog.exec() == QDialog.Accepted:
                future.set_result(dialog.code())
            else:
                future.set_result(None)
        except Exception:
            future.set_result(None)

    @Slot(bytes, str, str)
    def _handle_qr_image(self, image_bytes: bytes, login_url: str, image_url: str) -> None:
        pixmap = QPixmap()
        pixmap.loadFromData(image_bytes)
        self.qr_label.setPixmap(pixmap.scaled(self.qr_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
        instruction = f"Scan the QR code with your Xiaomi app.\nAlternate login URL: {login_url or image_url}"
        self.log_view.appendPlainText(instruction)

    def _populate_devices(self, data) -> None:
        self.device_tree.clear()
        if not data:
            return
        for server_entry in data:
            server_name = server_entry.get("server", "").upper()
            server_item = QTreeWidgetItem([server_name, "", "", "", "", "", ""])
            for home in server_entry.get("homes", []):
                home_label = f'Home {home.get("home_id", "")}'
                home_item = QTreeWidgetItem([home_label, "", "", "", "", "", ""])
                for device in home.get("devices", []):
                    ble_key = ""
                    if "BLE_DATA" in device:
                        ble_key = device["BLE_DATA"].get("beaconkey", "")
                    tree_item = QTreeWidgetItem(
                        [
                            device.get("name", ""),
                            device.get("did", ""),
                            device.get("token", ""),
                            device.get("localip", ""),
                            device.get("mac", ""),
                            device.get("model", ""),
                            ble_key,
                        ]
                    )
                    home_item.addChild(tree_item)
                server_item.addChild(home_item)
            self.device_tree.addTopLevelItem(server_item)
        self.device_tree.expandToDepth(1)

    @Slot()
    def _on_export_csv(self) -> None:
        """Export device tree data to CSV file."""
        # Open file dialog
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Devices to CSV",
            str(Path.home() / "xiaomi_devices.csv"),
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return  # User cancelled
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow([
                    'Server', 'Home ID', 'Device Name', 'Device ID', 
                    'Token', 'IP Address', 'MAC Address', 'Model', 'BLE Key'
                ])
                
                # Iterate through tree structure
                for server_idx in range(self.device_tree.topLevelItemCount()):
                    server_item = self.device_tree.topLevelItem(server_idx)
                    server_name = server_item.text(0)
                    
                    for home_idx in range(server_item.childCount()):
                        home_item = server_item.child(home_idx)
                        home_id = home_item.text(0)
                        
                        for device_idx in range(home_item.childCount()):
                            device_item = home_item.child(device_idx)
                            writer.writerow([
                                server_name,           # Server
                                home_id,               # Home ID
                                device_item.text(0),   # Device Name
                                device_item.text(1),   # Device ID
                                device_item.text(2),   # Token
                                device_item.text(3),   # IP Address
                                device_item.text(4),   # MAC Address
                                device_item.text(5),   # Model
                                device_item.text(6),   # BLE Key
                            ])
            
            self.log_view.appendPlainText(f"Devices exported to: {file_path}")
            QMessageBox.information(
                self, 
                "Export Successful", 
                f"Devices exported successfully to:\n{file_path}"
            )
            
        except Exception as e:
            self.log_view.appendPlainText(f"Export failed: {str(e)}")
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export devices:\n{str(e)}"
            )

    @Slot()
    def _on_export_json(self) -> None:
        """Export device data to JSON file."""
        if not self._device_data:
            QMessageBox.warning(self, "No Data", "No device data available to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Devices to JSON",
            str(Path.home() / "xiaomi_devices.json"),
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(self._device_data, jsonfile, indent=2, ensure_ascii=False)
            
            self.log_view.appendPlainText(f"Devices exported to JSON: {file_path}")
            QMessageBox.information(
                self,
                "Export Successful",
                f"Devices exported successfully to:\n{file_path}"
            )
        except Exception as e:
            self.log_view.appendPlainText(f"JSON export failed: {str(e)}")
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export devices to JSON:\n{str(e)}"
            )

    @Slot()
    def _on_export_yaml(self) -> None:
        """Export device data to YAML file."""
        if not self._device_data:
            QMessageBox.warning(self, "No Data", "No device data available to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Devices to YAML",
            str(Path.home() / "xiaomi_devices.yaml"),
            "YAML Files (*.yaml *.yml);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            # Try to import yaml, provide helpful error if not available
            try:
                import yaml
            except ImportError:
                QMessageBox.warning(
                    self,
                    "YAML Not Available",
                    "YAML export requires the PyYAML package.\n\n"
                    "The application was built without YAML support.\n"
                    "Please use JSON or CSV export instead."
                )
                return
            
            with open(file_path, 'w', encoding='utf-8') as yamlfile:
                yaml.dump(self._device_data, yamlfile, default_flow_style=False, allow_unicode=True)
            
            self.log_view.appendPlainText(f"Devices exported to YAML: {file_path}")
            QMessageBox.information(
                self,
                "Export Successful",
                f"Devices exported successfully to:\n{file_path}"
            )
        except Exception as e:
            self.log_view.appendPlainText(f"YAML export failed: {str(e)}")
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export devices to YAML:\n{str(e)}"
            )

    @Slot(object)
    def _show_context_menu(self, position) -> None:
        """Show context menu for the device tree."""
        item = self.device_tree.itemAt(position)
        if not item:
            return
        
        # Don't show menu for server or home items (only for actual devices)
        if item.childCount() > 0:
            return
        
        menu = QMenu(self)
        
        # Copy individual field actions
        copy_name = menu.addAction("Copy Name")
        copy_device_id = menu.addAction("Copy Device ID")
        copy_token = menu.addAction("Copy Token")
        copy_ip = menu.addAction("Copy IP Address")
        copy_mac = menu.addAction("Copy MAC Address")
        copy_model = menu.addAction("Copy Model")
        copy_ble = menu.addAction("Copy BLE Key")
        
        menu.addSeparator()
        
        # Copy entire row
        copy_row = menu.addAction("Copy Row (Tab-separated)")
        copy_all = menu.addAction("Copy All Selected Devices")
        
        # Execute menu and handle action
        action = menu.exec_(self.device_tree.viewport().mapToGlobal(position))
        
        if action == copy_name:
            self._copy_to_clipboard(item.text(0))
        elif action == copy_device_id:
            self._copy_to_clipboard(item.text(1))
        elif action == copy_token:
            self._copy_to_clipboard(item.text(2))
        elif action == copy_ip:
            self._copy_to_clipboard(item.text(3))
        elif action == copy_mac:
            self._copy_to_clipboard(item.text(4))
        elif action == copy_model:
            self._copy_to_clipboard(item.text(5))
        elif action == copy_ble:
            self._copy_to_clipboard(item.text(6))
        elif action == copy_row:
            self._copy_row_to_clipboard(item)
        elif action == copy_all:
            self._copy_selected_items()

    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard."""
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            self.log_view.appendPlainText(f"Copied to clipboard: {text[:50]}...")

    def _copy_row_to_clipboard(self, item: QTreeWidgetItem) -> None:
        """Copy entire row as tab-separated values."""
        row_data = []
        for col in range(7):
            row_data.append(item.text(col))
        
        text = "\t".join(row_data)
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.log_view.appendPlainText("Copied row to clipboard")

    @Slot()
    def _copy_selected_items(self) -> None:
        """Copy all selected device items to clipboard as tab-separated rows."""
        selected_items = self.device_tree.selectedItems()
        
        # Filter out server/home items, only keep device items
        device_items = [item for item in selected_items if item.childCount() == 0]
        
        if not device_items:
            self.log_view.appendPlainText("No devices selected to copy")
            return
        
        # Build tab-separated text with header
        lines = []
        lines.append("\t".join(["Name", "Device ID", "Token", "IP", "MAC", "Model", "BLE Key"]))
        
        for item in device_items:
            row_data = []
            for col in range(7):
                row_data.append(item.text(col))
            lines.append("\t".join(row_data))
        
        text = "\n".join(lines)
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.log_view.appendPlainText(f"Copied {len(device_items)} device(s) to clipboard")

    @Slot(str)
    def _filter_devices(self, search_text: str) -> None:
        """Filter devices in tree based on search text."""
        search_text = search_text.lower().strip()
        
        for server_idx in range(self.device_tree.topLevelItemCount()):
            server_item = self.device_tree.topLevelItem(server_idx)
            server_has_visible_device = False
            
            for home_idx in range(server_item.childCount()):
                home_item = server_item.child(home_idx)
                home_has_visible_device = False
                
                for device_idx in range(home_item.childCount()):
                    device_item = home_item.child(device_idx)
                    
                    # Check if any column matches the search text
                    if not search_text:
                        device_item.setHidden(False)
                        home_has_visible_device = True
                    else:
                        matches = False
                        for col in range(7):
                            if search_text in device_item.text(col).lower():
                                matches = True
                                break
                        
                        device_item.setHidden(not matches)
                        if matches:
                            home_has_visible_device = True
                
                # Hide home if no devices match
                home_item.setHidden(not home_has_visible_device)
                if home_has_visible_device:
                    server_has_visible_device = True
            
            # Hide server if no homes/devices match
            server_item.setHidden(not server_has_visible_device)

    def save_settings(self) -> None:
        """Save application settings and window state."""
        settings = QSettings("XiaomiTools", "TokenExtractor")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState())
        settings.setValue("splitterSizes", self.splitter.saveState())
        settings.setValue("lastPasswordServer", self.password_server_combo.currentData())
        settings.setValue("lastQRServer", self.qr_server_combo.currentData())
        settings.setValue("includeBLE", self.include_ble_checkbox.isChecked())
        settings.setValue("lastUsername", self.username_input.text())
        self.log_view.appendPlainText("Settings saved")

    def restore_settings(self) -> None:
        """Restore application settings and window state."""
        settings = QSettings("XiaomiTools", "TokenExtractor")
        
        geometry = settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
        window_state = settings.value("windowState")
        if window_state:
            self.restoreState(window_state)
        
        splitter_state = settings.value("splitterSizes")
        if splitter_state:
            self.splitter.restoreState(splitter_state)
        
        last_password_server = settings.value("lastPasswordServer")
        if last_password_server:
            index = self.password_server_combo.findData(last_password_server)
            if index >= 0:
                self.password_server_combo.setCurrentIndex(index)
        
        last_qr_server = settings.value("lastQRServer")
        if last_qr_server:
            index = self.qr_server_combo.findData(last_qr_server)
            if index >= 0:
                self.qr_server_combo.setCurrentIndex(index)
        
        include_ble = settings.value("includeBLE", True, type=bool)
        self.include_ble_checkbox.setChecked(include_ble)
        
        last_username = settings.value("lastUsername", "")
        if last_username:
            self.username_input.setText(last_username)
        
        self.log_view.appendPlainText("Settings restored")

    def closeEvent(self, event) -> None:
        """Handle application close gracefully."""
        # Cancel any ongoing workers
        if self._current_worker:
            self.log_view.appendPlainText("Cancelling ongoing operations...")
            self.pool.clear()
            self.pool.waitForDone(5000)  # Wait max 5 seconds
        
        # Save settings before closing
        self.save_settings()
        
        event.accept()


def run() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()



