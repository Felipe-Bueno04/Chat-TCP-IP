import socket      # Biblioteca para comunicação em rede
import threading   # Permite lidar com vários clientes ao mesmo tempo

# Configurações do servidor
HOST = '10.164.20.145'  # Endereço IP do servidor
PORT = 12345            # Porta do servidor que escuta
clients = []            # Lista com todos os clientes conectados
salas = {}              # Dicionário que guarda as salas (agrupadas por chave secreta)

# --- Funções do Servidor ---

# Função que trata cada cliente individualmente
def handle_client(conn, addr):
    print(f"Conexão estabelecida com {addr}")
    chave_hash = None  # Armazena a chave secreta do cliente

    while True:
        try:
            message = conn.recv(1024).decode('utf-8') # Recebe mensagem
            if not message:
                break

            # Primeiro pacote recebido deve ser a chave secreta (hash)
            if message.startswith("__HASH__"):
                chave_hash = message.replace("__HASH__", "")
                if chave_hash not in salas:
                    salas[chave_hash] = []      # Cria nova sala
                salas[chave_hash].append(conn)  # Adiciona cliente na sala
                print(f"Cliente {addr} entrou na sala {chave_hash[:8]}...")
            else:
                # Mostra a mensagem recebida (já criptografada)
                print(f"[Sala {chave_hash[:8]}] [Mensagem recebida] {message}")

                # Repassa a mensagem apenas para os clientes da mesma sala
                for client in salas.get(chave_hash, []):
                    if client != conn:
                        try:
                            client.send(message.encode('utf-8'))
                        except:
                            client.close()
                            salas[chave_hash].remove(client)
        except:
            break

    # Quando cliente desconecta → remove da sala
    conn.close()
    if chave_hash and conn in salas.get(chave_hash, []):
        salas[chave_hash].remove(conn)
        print(f"Cliente {addr} saiu da sala {chave_hash[:8]}")

# Função auxiliar para enviar mensagens para todos (não usada no código principal) 
def broadcast(message, connection):
    for client in clients:
        if client != connection:
            try:
                client.send(message.encode('utf-8'))
            except:
                client.close()
                clients.remove(client)


# Inicialização do servidor
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Cria socket TCP
server.bind((HOST, PORT))  # Associa o socket ao IP e porta definidos
server.listen()            # Coloca o servidor em modo de escuta
print(f"Servidor rodando em {HOST}:{PORT}")

# Laço principal: aceita conexões e cria uma thread para cada cliente
while True:
    conn, addr = server.accept() # Aceita nova conexão
    clients.append(conn)
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()
