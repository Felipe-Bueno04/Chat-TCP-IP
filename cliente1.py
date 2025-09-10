import socket
import threading
import cifras
import hashlib

HOST = '10.164.20.82'  # Endereço IP do servidor
PORT = 12345  # Porta do servidor
USER = "Maomao"  # Nome de usuário

print("Escolha a cifra:")
print("1 - César")
print("2 - Substituição Monoalfabética")
print("3 - Playfair")
print("4 - Vigenère")
print("5 - RC4")  # <<---- nova opção
opcao = input("Opção: ")

chave = input("Digite a chave secreta: ")
chave_hash = hashlib.sha256(chave.encode()).hexdigest()

# Mapear funções de criptografia/descriptografia
if opcao == '1':
    criptografar = lambda msg: cifras.cifra_cesar_criptografar(msg, int(chave))
    descriptografar = lambda msg: cifras.cifra_cesar_descriptografar(msg, int(chave))
elif opcao == '2':
    criptografar = lambda msg: cifras.substituicao_monoalfabetica_criptografar(msg, chave)
    descriptografar = lambda msg: cifras.substituicao_monoalfabetica_descriptografar(msg, chave)
elif opcao == '3':
    criptografar = lambda msg: cifras.playfair_criptografar(msg, chave)
    descriptografar = lambda msg: cifras.playfair_descriptografar(msg, chave)
elif opcao == '4':
    criptografar = lambda msg: cifras.vigenere_criptografar(msg, chave)
    descriptografar = lambda msg: cifras.vigenere_descriptografar(msg, chave)
elif opcao == '5':
    criptografar = lambda msg: cifras.rc4_criptografar(msg, chave)
    descriptografar = lambda msg: cifras.rc4_descriptografar(msg, chave)
else:
    print("Opção inválida. Usando César com chave 3.")
    criptografar = lambda msg: cifras.cifra_cesar_criptografar(msg, 3)
    descriptografar = lambda msg: cifras.cifra_cesar_descriptografar(msg, 3)

def _remove_playfair_padding(text):
    # remove o 'X' que foi usado como padding no final ou duplicatas
    return text.replace("X", "")

# --- Receber mensagens do servidor ---
def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break

            if ":" in data:
                sender, encrypted_msg = data.split(":", 1)
                decrypted = descriptografar(encrypted_msg.strip())
                decrypted = _remove_playfair_padding(decrypted)
                # primeira letra maiúscula, resto minúscula
                decrypted = decrypted.capitalize()
                print(f"\n{sender}: {decrypted}")
            else:
                decrypted = descriptografar(data.strip())
                decrypted = _remove_playfair_padding(decrypted)
                decrypted = decrypted.capitalize()
                print(f"\n{decrypted}")

        except:
            break

# --- Conecta ao servidor ---
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# envia hash da sala logo após conectar
client.send(f"__HASH__{chave_hash}".encode('utf-8'))

# inicia thread que recebe mensagens
receive_thread = threading.Thread(target=receive_messages, args=(client,))
receive_thread.start()

try:
    while True:
        message = input("Digite a mensagem para enviar (ou 'flw' para sair): ")
        messageInput = message

        # criptografa apenas a mensagem, sem o nome do usuário
        encrypted_msg = criptografar(message)
        # envia ao servidor: somente a mensagem criptografada
        client.send(encrypted_msg.encode('utf-8'))

        # mostra localmente a mensagem original com usuário
        print(f"\n{USER}: {message}")

        if messageInput.lower() == 'flw':
            break
finally:
    client.close()
