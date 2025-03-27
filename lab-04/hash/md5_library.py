import hashlib

def calculate_md5(input_string):
    # Khởi tạo đối tượng băm MD5
    md5_hash = hashlib.md5()  # Đảm bảo không ghi đè hashlib.md5
    # Cập nhật chuỗi đầu vào
    md5_hash.update(input_string.encode('utf-8'))
    # Trả về giá trị băm dưới dạng chuỗi hexa
    return md5_hash.hexdigest()

if __name__ == "__main__":
    input_string = input("Nhập chuỗi cần băm: ")
    md5_hash = calculate_md5(input_string)
    print("Mã băm MD5 của chuỗi '{}' là: {}".format(input_string, md5_hash))
