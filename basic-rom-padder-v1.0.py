import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit, QComboBox, QFileDialog, QMessageBox, QHBoxLayout

class romeditor(QWidget):
    def __init__(self):
        super().__init__()
        self.initui()

    def initui(self):
        self.setWindowTitle('Basic ROM Padder v1.0 by rarenight')
        self.setGeometry(100, 100, 400, 400)

        layout = QVBoxLayout()

        self.file_label = QLabel('No file selected')
        layout.addWidget(self.file_label)

        self.file_size_label = QLabel('Current file size: N/A')
        layout.addWidget(self.file_size_label)

        self.new_size_label = QLabel('New size after changes: N/A')
        layout.addWidget(self.new_size_label)

        self.select_file_button = QPushButton('Select ROM File')
        self.select_file_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_file_button)

        self.create_truncate_pad_inputs(layout, 'Truncate bytes from start:', 'truncate_start')
        self.create_truncate_pad_inputs(layout, 'Truncate bytes from end:', 'truncate_end')
        self.create_truncate_pad_inputs(layout, 'Pad bytes at start:', 'pad_start')
        self.create_truncate_pad_inputs(layout, 'Pad bytes at end:', 'pad_end')

        self.pad_byte_label = QLabel('Pad with byte:')
        layout.addWidget(self.pad_byte_label)
        self.pad_byte_combo = QComboBox()
        self.pad_byte_combo.addItems(['00', 'ff', 'Custom'])
        self.pad_byte_combo.currentIndexChanged.connect(self.toggle_custom_byte_input)
        layout.addWidget(self.pad_byte_combo)

        self.custom_byte_input = QLineEdit()
        self.custom_byte_input.setPlaceholderText('Enter custom byte in hex')
        self.custom_byte_input.setVisible(False)
        layout.addWidget(self.custom_byte_input)

        self.process_button = QPushButton('Process ROM File')
        self.process_button.clicked.connect(self.process_file)
        layout.addWidget(self.process_button)

        self.setLayout(layout)

    def create_truncate_pad_inputs(self, layout, label_text, attribute_prefix):
        label = QLabel(label_text)
        layout.addWidget(label)

        input_layout = QHBoxLayout()

        input_field = QLineEdit()
        input_field.textChanged.connect(self.update_new_size)
        setattr(self, f'{attribute_prefix}_input', input_field)
        input_layout.addWidget(input_field)

        format_combo = QComboBox()
        format_combo.addItems(['Dec', 'Hex'])
        format_combo.currentIndexChanged.connect(self.update_new_size)
        setattr(self, f'{attribute_prefix}_format', format_combo)
        input_layout.addWidget(format_combo)

        layout.addLayout(input_layout)

    def select_file(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file, _ = QFileDialog.getOpenFileName(self, "Select ROM File", "", "All Files (*);;", options=options)
        if file:
            self.file_path = file
            self.file_label.setText(file)
            self.file_size = os.path.getsize(file)
            self.file_size_label.setText(f'Current file size: {self.file_size} bytes')
            self.update_new_size()

    def toggle_custom_byte_input(self):
        if self.pad_byte_combo.currentText() == 'Custom':
            self.custom_byte_input.setVisible(True)
        else:
            self.custom_byte_input.setVisible(False)

    def parse_input(self, input_text, format_combo):
        if not input_text:
            return 0
        if format_combo.currentText() == 'Dec':
            return int(input_text)
        elif format_combo.currentText() == 'Hex':
            return int(input_text, 16)

    def update_new_size(self):
        if not hasattr(self, 'file_size'):
            return

        try:
            truncate_start = self.parse_input(self.truncate_start_input.text(), self.truncate_start_format)
            truncate_end = self.parse_input(self.truncate_end_input.text(), self.truncate_end_format)
            pad_start = self.parse_input(self.pad_start_input.text(), self.pad_start_format)
            pad_end = self.parse_input(self.pad_end_input.text(), self.pad_end_format)

            if truncate_start > self.file_size:
                truncate_start = self.file_size
            if truncate_end > self.file_size - truncate_start:
                truncate_end = self.file_size - truncate_start

            new_size = self.file_size - truncate_start - truncate_end + pad_start + pad_end
            self.new_size_label.setText(f'New size after changes: {new_size} bytes')

        except ValueError:
            self.new_size_label.setText('New size after changes: N/A')

    def process_file(self):
        if not hasattr(self, 'file_path'):
            QMessageBox.warning(self, 'Error', 'No file selected!')
            return

        try:
            truncate_start = self.parse_input(self.truncate_start_input.text(), self.truncate_start_format)
            truncate_end = self.parse_input(self.truncate_end_input.text(), self.truncate_end_format)
            pad_start = self.parse_input(self.pad_start_input.text(), self.pad_start_format)
            pad_end = self.parse_input(self.pad_end_input.text(), self.pad_end_format)
            pad_byte = self.pad_byte_combo.currentText()

            if pad_byte == 'Custom':
                pad_byte = self.custom_byte_input.text()
                if not pad_byte:
                    QMessageBox.warning(self, 'Error', 'Custom byte cannot be empty!')
                    return
                if len(pad_byte) != 2 or not all(c in '0123456789ABCDEFabcdef' for c in pad_byte):
                    QMessageBox.warning(self, 'Error', 'Custom byte must be a valid hex value (00-ff)!')
                    return

            pad_byte = bytes.fromhex(pad_byte)

            with open(self.file_path, 'rb') as f:
                rom_data = f.read()

            if truncate_start > len(rom_data):
                truncate_start = len(rom_data)
            if truncate_end > len(rom_data) - truncate_start:
                truncate_end = len(rom_data) - truncate_start

            rom_data = rom_data[truncate_start:len(rom_data) - truncate_end]
            rom_data = pad_byte * pad_start + rom_data + pad_byte * pad_end

            output_file = self.file_path[:-4] + '_modified' + self.file_path[-4:]
            with open(output_file, 'wb') as f:
                f.write(rom_data)

            QMessageBox.information(self, 'Success', f'File processed and saved as {output_file}')

        except ValueError:
            QMessageBox.warning(self, 'Error', 'Invalid input! Please enter valid numbers for truncation and padding.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = romeditor()
    ex.show()
    sys.exit(app.exec_())
