import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.caesar import Ui_MainWindow
import requests

class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        # Sửa tên nút để khớp với tệp giao diện
        self.ui.btnencrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btndecrypt.clicked.connect(self.call_api_decrypt)

    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/caesar/encrypt"
        payload = {
            'plain_text': self.ui.txtplaintext.toPlainText(),  # Sửa tên thành txtplaintext
            'key': self.ui.txtkey.toPlainText()  # Đảm bảo txtkey là đúng
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txtciphertext.setPlainText(data['encrypted_message'])  # Sử dụng setPlainText thay vì setText
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Encryption Success")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/caesar/decrypt"
        payload = {
            'cipher_text': self.ui.txtciphertext.toPlainText(),  # Sửa tên thành txtciphertext
            'key': self.ui.txtkey.toPlainText()  # Đảm bảo txtkey là đúng
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txtplaintext.setPlainText(data['decrypted_message'])  # Sử dụng setPlainText thay vì setText
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Information)
                msg.setText("Decryption Success")
                msg.exec_()
            else:
                print("Error while calling API")
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())