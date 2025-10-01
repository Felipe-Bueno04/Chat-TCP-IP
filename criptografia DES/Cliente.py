import socket
from cifras import des_criptografar, des_decifrar

HOST = '127.0.0.1'
PORT = 5000
KEY = "0123456789ABCDEF"  

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    while True:
        msg = input("Digite a mensagem (ou 'sair'): ")
        if msg == "sair":
            break

        cipher_hex = des_criptografar(msg, KEY)

        s.sendall(cipher_hex.encode())

        data = s.recv(1024).decode()

        plain = des_decifrar(data, KEY)
        print(f"Recebido (cifrado): {data}")
        print(f"Decifrado: {plain}")

    s.close()

if __name__ == "__main__":
    main()
