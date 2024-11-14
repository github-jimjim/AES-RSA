import sys
from Crypto.PublicKey import RSA
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QProgressBar, QLineEdit, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime
import multiprocessing
import cpuinfo
import platform
import winsound
import time

def get_cpu_description():
    return platform.processor()

def play_beep():
    winsound.Beep(1000, 1000)

def get_cpu_model():
    return cpuinfo.get_cpu_info()["brand_raw"]

class KeyGeneratorThread(QThread):
    progress = pyqtSignal(int)

    def __init__(self, bits):
        super().__init__()
        self.bits = bits

    def run(self):
        key = RSA.generate(self.bits)
        self.progress.emit(25)  # Emit 25% for key generation

        # Save private key
        with open('priv.key', 'wb') as priv_file:
            priv_file.write(key.export_key())
            self.progress.emit(50)  # Emit 50% after saving private key

        # Save public key
        with open('pub.key', 'wb') as pub_file:
            pub_file.write(key.publickey().export_key())
            self.progress.emit(75)  # Emit 75% after saving public key

        # Save key length
        with open('key_length.txt', 'w') as text_file:
            text_file.write(str(self.bits))
            self.progress.emit(100)  # Emit 100% after saving key length

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('RSA Key Generator')
        self.layout = QVBoxLayout()

        self.label = QLabel('Enter desired key length in bits (e.g., 2048, 4096):')
        self.layout.addWidget(self.label)

        self.key_length_input = QLineEdit(self)
        self.layout.addWidget(self.key_length_input)

        self.label_cores = QLabel('Enter number of CPU cores to use:')
        self.layout.addWidget(self.label_cores)

        self.cores_input = QLineEdit(self)
        self.layout.addWidget(self.cores_input)

        self.progress_bar = QProgressBar(self)
        self.layout.addWidget(self.progress_bar)

        self.button = QPushButton('Generate Key', self)
        self.button.clicked.connect(self.generate_key)
        self.layout.addWidget(self.button)

        self.setLayout(self.layout)

    def generate_key(self):
        try:
            bits = int(self.key_length_input.text())
            num_processes = int(self.cores_input.text())

            if bits <= 0:
                raise ValueError("Key length must be a positive integer.")
            if num_processes <= 0 or num_processes > multiprocessing.cpu_count():
                raise ValueError("Invalid number of CPU cores.")

            self.progress_bar.setValue(0)

            self.thread = KeyGeneratorThread(bits)
            self.thread.progress.connect(self.update_progress)
            self.thread.finished.connect(self.key_generation_finished)
            self.thread.start()

        except ValueError as e:
            QMessageBox.critical(self, "Input Error", str(e))

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def key_generation_finished(self):
        play_beep()
        QMessageBox.information(self, "Success", "RSA key generation completed!")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    cpu_info = get_cpu_model()
    cpu_description = get_cpu_description()
    print("Your CPU: " + cpu_info)  # Only for initial info
    print("Your CPU description: " + cpu_description)  # Only for initial info
    print("Available CPU cores: " + str(multiprocessing.cpu_count()))  # Only for initial info

    main_app = App()
    main_app.resize(400, 200)
    main_app.show()

    sys.exit(app.exec_())
