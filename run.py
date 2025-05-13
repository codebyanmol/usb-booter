import sys
import os
import subprocess
import logging
import hashlib
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QPushButton, QComboBox, QCheckBox, QProgressBar,
                             QTextEdit, QFileDialog, QMessageBox, QGroupBox)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QPalette, QColor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('usb_creator.log'),
        logging.StreamHandler()
    ]
)

class USBDriveManager:
    """Handles USB drive detection and operations"""
    
    @staticmethod
    def detect_usb_drives():
        """Detect available USB drives"""
        try:
            if sys.platform == 'linux':
                # For Linux and Termux
                result = subprocess.run(['lsblk', '-d', '-o', 'NAME,RO,RM,SIZE,MODEL'], 
                                      capture_output=True, text=True)
                drives = []
                for line in result.stdout.splitlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == '1':  # RM=1 means removable
                        drive = {
                            'device': f"/dev/{parts[0]}",
                            'readonly': parts[1] == '1',
                            'size': parts[3],
                            'model': ' '.join(parts[4:]) if len(parts) > 4 else 'Unknown'
                        }
                        drives.append(drive)
                return drives
            elif sys.platform == 'win32':
                # Windows implementation would go here
                return []
            else:
                return []
        except Exception as e:
            logging.error(f"Error detecting USB drives: {e}")
            return []

    @staticmethod
    def format_drive(device, fs_type='fat32'):
        """Format a USB drive"""
        try:
            if sys.platform == 'linux':
                # Unmount all partitions first
                subprocess.run(['umount', f"{device}*"], stderr=subprocess.DEVNULL)
                
                # Create partition table and single partition
                commands = [
                    f"parted {device} --script mklabel msdos",
                    f"parted {device} --script mkpart primary {fs_type} 1MiB 100%",
                    f"mkfs.{fs_type} {device}1"
                ]
                
                for cmd in commands:
                    result = subprocess.run(cmd, shell=True, check=True)
                    if result.returncode != 0:
                        raise Exception(f"Command failed: {cmd}")
                
                return True
            else:
                logging.warning("Formatting only supported on Linux currently")
                return False
        except Exception as e:
            logging.error(f"Error formatting drive: {e}")
            return False

    @staticmethod
    def write_iso(device, iso_path, use_dd=True):
        """Write ISO to USB drive"""
        try:
            if sys.platform == 'linux':
                if use_dd:
                    # Using dd for raw writing
                    cmd = f"dd if={iso_path} of={device} bs=4M status=progress"
                else:
                    # Alternative method using cat
                    cmd = f"cat {iso_path} > {device}"
                
                result = subprocess.run(cmd, shell=True, check=True)
                return result.returncode == 0
            else:
                logging.warning("ISO writing only supported on Linux currently")
                return False
        except Exception as e:
            logging.error(f"Error writing ISO: {e}")
            return False

    @staticmethod
    def install_ventoy(device):
        """Install Ventoy to USB drive"""
        try:
            # Check if Ventoy script exists in the same directory
            ventoy_path = os.path.join(os.path.dirname(__file__), 'ventoy', 'Ventoy2Disk.sh')
            if not os.path.exists(ventoy_path):
                logging.error("Ventoy installation files not found")
                return False
                
            cmd = f"sh {ventoy_path} -i {device}"
            result = subprocess.run(cmd, shell=True, check=True)
            return result.returncode == 0
        except Exception as e:
            logging.error(f"Error installing Ventoy: {e}")
            return False

    @staticmethod
    def calculate_sha256(file_path):
        """Calculate SHA256 checksum of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


class WorkerThread(QThread):
    """Background worker thread for long-running operations"""
    progress = pyqtSignal(int)
    message = pyqtSignal(str)
    finished = pyqtSignal(bool)
    
    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
    
    def run(self):
        try:
            if self.operation == 'format':
                success = USBDriveManager.format_drive(*self.args)
            elif self.operation == 'write_iso':
                success = USBDriveManager.write_iso(*self.args)
            elif self.operation == 'install_ventoy':
                success = USBDriveManager.install_ventoy(*self.args)
            else:
                success = False
                
            self.finished.emit(success)
        except Exception as e:
            self.message.emit(f"Error: {str(e)}")
            self.finished.emit(False)


class BootableUSBCreator(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.iso_path = None
        self.dark_mode = False
        self.setup_ui()
        self.refresh_usb_drives()
        
    def setup_ui(self):
        """Initialize the UI components"""
        self.setWindowTitle("Bootable USB Creator")
        self.setMinimumSize(600, 500)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # ISO Selection
        iso_group = QGroupBox("ISO File")
        iso_layout = QVBoxLayout()
        
        self.iso_label = QLabel("No ISO file selected")
        iso_layout.addWidget(self.iso_label)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.select_iso)
        iso_layout.addWidget(browse_btn)
        
        checksum_btn = QPushButton("Verify Checksum")
        checksum_btn.clicked.connect(self.verify_checksum)
        iso_layout.addWidget(checksum_btn)
        
        iso_group.setLayout(iso_layout)
        layout.addWidget(iso_group)
        
        # USB Drive Selection
        usb_group = QGroupBox("USB Drive")
        usb_layout = QVBoxLayout()
        
        self.usb_dropdown = QComboBox()
        self.usb_dropdown.setToolTip("Select USB drive to use")
        usb_layout.addWidget(self.usb_dropdown)
        
        refresh_btn = QPushButton("Refresh Drives")
        refresh_btn.clicked.connect(self.refresh_usb_drives)
        usb_layout.addWidget(refresh_btn)
        
        usb_group.setLayout(usb_layout)
        layout.addWidget(usb_group)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        
        self.format_check = QCheckBox("Format drive before writing")
        self.format_check.setChecked(True)
        options_layout.addWidget(self.format_check)
        
        self.fs_type_dropdown = QComboBox()
        self.fs_type_dropdown.addItems(["FAT32", "NTFS"])
        options_layout.addWidget(self.fs_type_dropdown)
        
        self.ventoy_check = QCheckBox("Install Ventoy (for multi-boot)")
        options_layout.addWidget(self.ventoy_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Actions
        actions_group = QGroupBox("Actions")
        actions_layout = QHBoxLayout()
        
        self.create_btn = QPushButton("Create Bootable USB")
        self.create_btn.clicked.connect(self.create_bootable_usb)
        actions_layout.addWidget(self.create_btn)
        
        self.eject_btn = QPushButton("Eject USB")
        self.eject_btn.clicked.connect(self.eject_usb)
        actions_layout.addWidget(self.eject_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Progress
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Log
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Menu
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        
        dark_mode_action = file_menu.addAction("Toggle Dark Mode")
        dark_mode_action.triggered.connect(self.toggle_dark_mode)
        
        about_action = file_menu.addAction("About")
        about_action.triggered.connect(self.show_about)
        
        # Initial UI state
        self.update_ui_state()
        
    def toggle_dark_mode(self):
        """Toggle between dark and light mode"""
        self.dark_mode = not self.dark_mode
        
        palette = QPalette()
        if self.dark_mode:
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(25, 25, 25))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.black)
        else:
            palette = QApplication.style().standardPalette()
            
        QApplication.setPalette(palette)
        
    def update_ui_state(self):
        """Update UI elements based on current state"""
        has_iso = self.iso_path is not None
        has_usb = self.usb_dropdown.count() > 0
        
        self.create_btn.setEnabled(has_iso and has_usb)
        self.eject_btn.setEnabled(has_usb)
        
    def log_message(self, message):
        """Add a message to the log area"""
        self.log_area.append(message)
        self.statusBar().showMessage(message)
        logging.info(message)
        
    def refresh_usb_drives(self):
        """Refresh the list of available USB drives"""
        self.usb_dropdown.clear()
        drives = USBDriveManager.detect_usb_drives()
        
        if not drives:
            self.log_message("No USB drives detected")
            return
            
        for drive in drives:
            display_text = f"{drive['device']} - {drive['size']} - {drive['model']}"
            if drive['readonly']:
                display_text += " (Read-Only)"
            self.usb_dropdown.addItem(display_text, drive['device'])
            
        self.log_message(f"Found {len(drives)} USB drive(s)")
        self.update_ui_state()
        
    def select_iso(self):
        """Select an ISO file"""
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("ISO Files (*.iso)")
        
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                self.iso_path = selected_files[0]
                self.iso_label.setText(os.path.basename(self.iso_path))
                self.log_message(f"Selected ISO: {self.iso_path}")
                self.update_ui_state()
                
    def verify_checksum(self):
        """Verify the checksum of the selected ISO"""
        if not self.iso_path:
            QMessageBox.warning(self, "Warning", "No ISO file selected")
            return
            
        try:
            checksum = USBDriveManager.calculate_sha256(self.iso_path)
            self.log_message(f"SHA256 checksum: {checksum}")
            
            # Show checksum in a dialog
            msg = QMessageBox()
            msg.setWindowTitle("ISO Checksum")
            msg.setText(f"SHA256: {checksum}")
            msg.setDetailedText(f"File: {self.iso_path}\nSHA256: {checksum}")
            msg.exec_()
        except Exception as e:
            self.log_message(f"Error calculating checksum: {e}")
            QMessageBox.critical(self, "Error", f"Failed to calculate checksum: {e}")
            
    def create_bootable_usb(self):
        """Create bootable USB drive"""
        if not self.iso_path or self.usb_dropdown.count() == 0:
            return
            
        selected_index = self.usb_dropdown.currentIndex()
        device = self.usb_dropdown.itemData(selected_index)
        
        if not device:
            self.log_message("No USB device selected")
            return
            
        # Confirm operation
        reply = QMessageBox.question(
            self, 'Confirmation',
            f"THIS WILL ERASE ALL DATA ON {device}!\nAre you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        self.log_message(f"Starting bootable USB creation on {device}")
        
        # Determine operations to perform
        operations = []
        if self.ventoy_check.isChecked():
            operations.append(('install_ventoy', device))
        else:
            if self.format_check.isChecked():
                fs_type = self.fs_type_dropdown.currentText().lower()
                operations.append(('format', device, fs_type))
            operations.append(('write_iso', device, self.iso_path))
        
        # Execute operations in sequence
        self.execute_operations(operations)
        
    def execute_operations(self, operations):
        """Execute a list of operations in sequence"""
        if not operations:
            return
            
        operation, *args = operations[0]
        
        self.worker_thread = WorkerThread(operation, *args)
        self.worker_thread.message.connect(self.log_message)
        self.worker_thread.finished.connect(
            lambda success: self.on_operation_finished(success, operations[1:])
        )
        self.worker_thread.start()
        
        # Disable UI during operation
        self.set_ui_enabled(False)
        
    def on_operation_finished(self, success, remaining_operations):
        """Handle completion of an operation"""
        if success:
            if remaining_operations:
                self.execute_operations(remaining_operations)
            else:
                self.log_message("All operations completed successfully!")
                QMessageBox.information(self, "Success", "Bootable USB created successfully!")
        else:
            self.log_message("Operation failed")
            QMessageBox.critical(self, "Error", "Operation failed. Check logs for details.")
            
        # Re-enable UI
        self.set_ui_enabled(True)
        
    def set_ui_enabled(self, enabled):
        """Enable or disable UI elements"""
        self.create_btn.setEnabled(enabled)
        self.eject_btn.setEnabled(enabled)
        self.usb_dropdown.setEnabled(enabled)
        self.format_check.setEnabled(enabled)
        self.fs_type_dropdown.setEnabled(enabled)
        self.ventoy_check.setEnabled(enabled)
        
    def eject_usb(self):
        """Eject the selected USB drive"""
        selected_index = self.usb_dropdown.currentIndex()
        device = self.usb_dropdown.itemData(selected_index)
        
        if not device:
            return
            
        try:
            if sys.platform == 'linux':
                subprocess.run(['udisksctl', 'power-off', '-b', device], check=True)
                self.log_message(f"Ejected {device} successfully")
            else:
                self.log_message("Eject not supported on this platform")
        except Exception as e:
            self.log_message(f"Error ejecting USB: {e}")
            
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>Bootable USB Creator</h2>
        <p>A tool to create bootable USB drives from ISO files.</p>
        <p>Supports:</p>
        <ul>
            <li>Direct ISO writing (dd-style)</li>
            <li>Ventoy multi-boot installation</li>
            <li>Drive formatting</li>
            <li>Checksum verification</li>
        </ul>
        <p>Works on Linux, Windows, and Android (via Termux).</p>
        """
        
        QMessageBox.about(self, "About Bootable USB Creator", about_text)
        
    def closeEvent(self, event):
        """Handle window close event"""
        # Clean up any resources if needed
        event.accept()


def main():
    """Main application entry point"""
    # Check if running in Termux
    if 'ANDROID_ROOT' in os.environ:
        os.environ['QT_QPA_PLATFORM'] = 'xcb'
        logging.info("Running in Termux environment")
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style that works well with dark mode
    
    # Set default font size for better readability
    font = QFont()
    font.setPointSize(10)
    app.setFont(font)
    
    window = BootableUSBCreator()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
