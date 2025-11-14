from __future__ import annotations

import re
import sys
import threading
from dataclasses import dataclass
from typing import Iterable, List, Optional

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
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
            self.signals.error.emit(str(exc))
        except Exception as exc:  # pragma: no cover - defensive logging
            self.signals.error.emit(str(exc))


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
        self._build_ui()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)

        self.tabs = QTabWidget()
        self._build_password_tab()
        self._build_qr_tab()
        root_layout.addWidget(self.tabs)

        splitter = QSplitter(Qt.Vertical)

        self.device_tree = QTreeWidget()
        self.device_tree.setColumnCount(7)
        self.device_tree.setHeaderLabels(["Name", "Device ID", "Token", "IP", "MAC", "Model", "BLE Key"])
        splitter.addWidget(self.device_tree)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        splitter.addWidget(self.log_view)
        splitter.setSizes([500, 200])

        root_layout.addWidget(splitter)

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
        QApplication.setOverrideCursor(Qt.WaitCursor if busy else Qt.ArrowCursor)

    @Slot(str)
    def _append_log(self, message: str) -> None:
        clean = ANSI_ESCAPE_RE.sub("", message)
        if clean:
            self.log_view.appendPlainText(clean)

    @Slot(object)
    def _handle_finished(self, data) -> None:
        self._set_busy(False)
        self._populate_devices(data)
        self.log_view.appendPlainText("Extraction completed.")
        QApplication.restoreOverrideCursor()

    @Slot(str)
    def _handle_error(self, message: str) -> None:
        self._set_busy(False)
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


def run() -> None:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run()



