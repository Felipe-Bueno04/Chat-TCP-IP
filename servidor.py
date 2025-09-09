import socket
import threading

HOST = '192.168.137.1'  # Endereço IP do servidor
PORT = 12345  # Porta do servidor
clients = []
salas = {}

# --- Funções do servidor ---
def handle_client(conn, addr):
    print(f"Conexão estabelecida com {addr}")
    chave_hash = None  # hash da chave secreta que o cliente enviará primeiro

    while True:
        try:
            message = conn.recv(1024).decode('utf-8')
            if not message:
                break

            # Primeiro pacote deve ser o hash da chave
            if message.startswith("__HASH__"):
                chave_hash = message.replace("__HASH__", "")
                if chave_hash not in salas:
                    salas[chave_hash] = []
                salas[chave_hash].append(conn)
                print(f"Cliente {addr} entrou na sala {chave_hash[:8]}...")
            else:
                # O servidor só mostra a mensagem recebida (criptografada)
                print(f"[Sala {chave_hash[:8]}] [Mensagem recebida] {message}")

                # Repassa só para clientes na mesma sala
                for client in salas.get(chave_hash, []):
                    if client != conn:
                        try:
                            client.send(message.encode('utf-8'))
                        except:
                            client.close()
                            salas[chave_hash].remove(client)
        except:
            break

    # --- desconexão ---
    conn.close()
    if chave_hash and conn in salas.get(chave_hash, []):
        salas[chave_hash].remove(conn)
        print(f"Cliente {addr} saiu da sala {chave_hash[:8]}")


def broadcast(message, connection):
    for client in clients:
        if client != connection:
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                clients.remove(client)


# --- Inicializar servidor ---
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print(f"Servidor rodando em {HOST}:{PORT}")

while True:
    conn, addr = server.accept()
    clients.append(conn)
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()
