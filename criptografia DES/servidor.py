import socket

HOST = '127.0.0.1'
PORT = 5000

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)

    print("Servidor esperando conexão...")
    conn, addr = s.accept()
    print("Conectado em", addr)

    while True:
        data = conn.recv(1024)
        if not data:
            break
        msg = data.decode()
        print(f"Mensagem cifrada recebida (hex): {msg}")
        conn.sendall(data)

    conn.close()

if __name__ == "__main__":
    main()
