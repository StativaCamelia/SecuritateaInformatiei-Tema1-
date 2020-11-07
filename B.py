import socket
import threading
from base64 import b64decode
from Crypto.Cipher import AES

HOST_KM = 'localhost'
PORT_KM = 9991
K3 = 'FE8CBA98765432100123456789ABC7EF'
iv = '0' * 16

def option_valid(opt):
    opt = str(opt)
    return True if opt.upper().endswith("ECB") or opt.upper().endswith("OFB") else False


def pad(text):
    if len(text) % 16 == 0:
        return text
    data = text + (16 - (len(text) % 16)) * b'\x00'
    return data


def recv_msg_A(conn):
    global iv
    global operation_mode
    complete_text = []
    while True:
        received = conn.recv(1024)
        received = received.decode()
        if not received:
            break
        if received == ' ':
            pass
        else:
            if "[MODE]" in received:
                iv = '0' * 16
                complete_text = []
                operation_mode = received.split()[-1]
                if option_valid(operation_mode):
                    print("Am primit de la A modul de operare: " + operation_mode)
                    s_km.sendall("[B] [KEY]: {}".format(operation_mode).encode())
                else:
                    conn.sendall("[B] [ERROR]: Modul de criptare introdus nu exista incearca iar".encode())
            else:
                received = received[:]
                if operation_mode == "ECB":
                    for i in range(len(received) // 25):
                        print(received[i * 25:(i+1) * 25])
                        decrypted = decrypt_text_ECB(received[i * 25:(i+1) * 25])
                        complete_text.append(decrypted)
                        print("Text Decrypted: {}\n".format(decrypted))
                else:
                    for i in range(len(received) // 25):
                        print(received[i * 25:(i + 1) * 25])
                        decrypted = decrypt_text_OFB(received[i * 25:(i+1) * 25])
                        complete_text.append(decrypted)
                        print("Text Decrypted: {}".format(decrypted))
                print('Status text: {}'.format("".join(complete_text)))


#Decriptam cate un bloc pe rand
def decrypt_text_ECB(text):
    global key_decrypted
    text = b64decode(text)
    cipher = AES.new(key_decrypted.encode('utf8'), AES.MODE_ECB)
    return cipher.decrypt(text).decode('utf8')


def XOR(input, key):
    index = 0
    output_bytes = b''
    for byte in input:
        if index >= len(key):
            index = 0
        output_bytes += bytes([byte ^ key[index]])
        index += 1
    return output_bytes


def decrypt_text_OFB(text):
    global key_decrypted
    global iv
    cipher = AES.new(key_decrypted.encode('utf8'), AES.MODE_ECB)
    iv = cipher.encrypt(iv)
    decrypt = XOR(b64decode(text), iv)
    return decrypt.decode('utf-8')


# Stim ca avem chei de dimensiune fixa asa ca nu mai impartim pe blocuri doar decriptam(implementare pentru decriptare ECB cu mai multe blocuri in nodul B)
def decrypt_key_ECB(key):
    return AES.new(K3.encode('utf8'), AES.MODE_ECB).decrypt(b64decode(key)).decode('utf8')


# Stim ca avem chei de dimensiune fixa asa ca nu mai impartim pe blocuri doar decripta(implementare pentru decriptare OFB cu mai multe blocuri in nodul B)
def decrypt_key_OFB(key):
    iv = '0' * 16
    cipher = AES.new(K3.encode('utf8'), AES.MODE_ECB)
    iv = cipher.encrypt(iv)
    decrypt = XOR(b64decode(key), iv)
    return decrypt.decode('utf8')

def recv_msg_KM(conn):
    global key_decrypted
    while True:
        received = conn.recv(1024)
        received = received.decode()
        if not received:
            break
        if received == ' ':
            pass
        else:
            print(received)
            key = received.split()[-1]
            if operation_mode == "ECB":
                key_decrypted = decrypt_key_ECB(key)
                print("Key Decrypted: {}".format(key_decrypted))
                send_msg(conn)
            else:
                key_decrypted = decrypt_key_OFB(key)
                print("Key Decrypted: {}".format(key_decrypted))
                send_msg(conn)


def send_msg(conn):
    conn.sendall("[B]: Start".encode())


if __name__ == '__main__':
    operation_mode = ''
    key_decrypted = ''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 9997))
    s.listen(10)
    print("Listening on localhost, PORT = 9997")
    (conn, addr) = s.accept()

    s_km = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_km.connect((HOST_KM, PORT_KM))

    thread1 = threading.Thread(target=recv_msg_A, args=([conn]))
    thread2 = threading.Thread(target=send_msg, args=([conn]))
    thread3 = threading.Thread(target=recv_msg_KM, args=([s_km]))
    try:
        thread1.start()
        thread2.start()
        thread3.start()
    except KeyboardInterrupt:
        thread1.join()
        thread2.join()
        thread3.join()
