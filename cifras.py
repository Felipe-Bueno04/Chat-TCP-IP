def cifra_cesar_criptografar(texto, chave):
    resultado = ""
    for char in texto:
        if char.isalpha():
            start = ord("a") if char.islower() else ord("A")
            resultado += chr((ord(char) - start + chave) % 26 + start)
        else:
            resultado += char
    return resultado

def cifra_cesar_descriptografar(texto, chave):
    resultado = ""
    for char in texto:
        if char.isalpha():
            start = ord("a") if char.islower() else ord("A")
            resultado += chr((ord(char) - start - chave) % 26 + start)
        else:
            resultado += char
    return resultado

def substituicao_monoalfabetica_criptografar(texto, chave):
    alfabeto = "abcdefghijklmnopqrstuvwxyz"
    chave_maiuscula = chave.upper()
    chave_minuscula = chave.lower()
    resultado = ""
    for char in texto:
        if char.isalpha():
            if char.islower():
                index = alfabeto.find(char)
                if index != -1:
                    resultado += chave_minuscula[index]
                else:
                    resultado += char
            else:
                index = alfabeto.upper().find(char)
                if index != -1:
                    resultado += chave_maiuscula[index]
                else:
                    resultado += char
        else:
            resultado += char
    return resultado

def substituicao_monoalfabetica_descriptografar(texto, chave):
    alfabeto = "abcdefghijklmnopqrstuvwxyz"
    chave_maiuscula = chave.upper()
    chave_minuscula = chave.lower()
    resultado = ""
    for char in texto:
        if char.isalpha():
            if char.islower():
                index = chave_minuscula.find(char)
                if index != -1:
                    resultado += alfabeto[index]
                else:
                    resultado += char
            else:
                index = chave_maiuscula.find(char)
                if index != -1:
                    resultado += alfabeto.upper()[index]
                else:
                    resultado += char
        else:
            resultado += char
    return resultado


# ---------------- PLAYFAIR ---------------- #
import unicodedata # Biblioteca usada para normalizar strings e remover acentos

def _normalize_text(text): # Função que normaliza o texto:
    
    # - Remove acentos
    # - Deixa todas as letras maiúsculas
    # - Substitui J por I (regra da cifra Playfair)
    normalized = unicodedata.normalize('NFD', text)
    filtered = ''.join(c for c in normalized if c.isalpha())
    return filtered.upper().replace('J', 'I')

def _generate_key_matrix(key): # Gera a matriz 5x5 usada na cifra Playfair a partir da chave

    key = _normalize_text(key) # Normaliza a chave
    seen = set() # Conjunto para evitar letras repetidas
    seq = [] # Lista com a sequência de letras da matriz

    # Adiciona letras da chave sem repetição
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            seq.append(ch)

    # Completa a matriz com as demais letras do alfabeto (sem J)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.add(ch)
            seq.append(ch)

    # Cria a matriz 5x5
    matrix = [seq[i*5:(i+1)*5] for i in range(5)]

    # Dicionário que guarda a posição (linha, coluna) de cada letra
    positions = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    return matrix, positions

def playfair_criptografar(text, key):
    """
    Criptografa o texto com a cifra Playfair.
    - Mantém espaços e pontuação
    - Forma pares de letras (digráfos), inserindo 'X' se necessário
    """
    matrix, pos = _generate_key_matrix(key) # Gera matriz a partir da chave
    out = [] # Lista que guardará o texto cifrado
    i = 0
    n = len(text)

    while i < n:
        # Se o caractere não for letra, apenas mantém
        if not text[i].isalpha():
            out.append(text[i])
            i += 1
            continue

        # Agrupa sequência de letras (ignora pontuação)
        j = i
        while j < n and text[j].isalpha():
            j += 1
        block = text[i:j]               # Bloco original
        norm = _normalize_text(block)   # Normaliza bloco para A-Z
        
        # Monta os pares de letras (digráfos)
        k = 0
        digraphs = []
        while k < len(norm):
            a = norm[k]
            if k + 1 < len(norm):
                b = norm[k+1]
                if a == b: # Caso de letras iguais → insere 'X'
                    digraphs.append(a + 'X')
                    k += 1
                else:
                    digraphs.append(a + b) # Caso de letras diferentes
                    k += 2
            else:
                digraphs.append(a + 'X') # Última letra sem par → adiciona 'X'
                k += 1

        # Aplica as regras da cifra Playfair em cada par
        for dg in digraphs:
            a, b = dg[0], dg[1]
            ra, ca = pos[a] # Posição da letra A
            rb, cb = pos[b] # Posição da letra B

            if ra == rb: # Mesma linha → pega a letra à direita
                out.append(matrix[ra][(ca+1) % 5])
                out.append(matrix[rb][(cb+1) % 5])

            elif ca == cb: # Mesma coluna → pega a letra abaixo
                out.append(matrix[(ra+1) % 5][ca])
                out.append(matrix[(rb+1) % 5][cb])

            else: # Retângulo → troca as colunas
                out.append(matrix[ra][cb])
                out.append(matrix[rb][ca])

        i = j  # Avança para o próximo bloco

    return ''.join(out) # Retorna o texto cifrado


def playfair_descriptografar(cipher_text, key):
    """
    Descriptografa preservando caracteres não-alfabéticos.
    Espera que os blocos de letras venham como pares contínuos (sem espaços),
    e que não-alfabéticos estejam no lugar original (ex.: espaços).
    """
    matrix, pos = _generate_key_matrix(key) # Gera matriz da chave
    out = []
    i = 0
    n = len(cipher_text)
    while i < n:
        if not cipher_text[i].isalpha(): 
            out.append(cipher_text[i]) # Mantém espaços/pontuação
            i += 1
            continue

        # Agrupa letras cifradas
        j = i
        while j < n and cipher_text[j].isalpha():
            j += 1
        block = cipher_text[i:j]  # deve ter comprimento par (evento quando padding X foi usado)
        k = 0
        while k < len(block):
            # Pega dois caracteres cifrados e descriptografa em dois plaintexts
            a = block[k]
            b = block[k+1]
            ra, ca = pos[a]
            rb, cb = pos[b]
            
            if ra == rb: # Mesma linha → pega a letra à esquerda
                out.append(matrix[ra][(ca-1) % 5])
                out.append(matrix[rb][(cb-1) % 5])

            elif ca == cb: # Mesma coluna → pega a letra acima
                out.append(matrix[(ra-1) % 5][ca])
                out.append(matrix[(rb-1) % 5][cb])

            else: # Retângulo → troca as colunas
                out.append(matrix[ra][cb])
                out.append(matrix[rb][ca])
            k += 2

        i = j

    return ''.join(out) # Retorna o texto descriptografado


# ---------------- VIGENERE ---------------- #
def vigenere_criptografar(texto, chave):
    resultado = ""
    chave = chave.upper()
    chave_idx = 0
    for char in texto:
        if char.isalpha():
            start = ord("a") if char.islower() else ord("A")
            chave_offset = ord(chave[chave_idx % len(chave)]) - ord("A")
            if char.islower():
                resultado += chr((ord(char) - start + chave_offset) % 26 + start)
            else:
                resultado += chr((ord(char) - start + chave_offset) % 26 + start)
            chave_idx += 1
        else:
            resultado += char
    return resultado

def vigenere_descriptografar(texto, chave):
    resultado = ""
    chave = chave.upper()
    chave_idx = 0
    for char in texto:
        if char.isalpha():
            start = ord("a") if char.islower() else ord("A")
            chave_offset = ord(chave[chave_idx % len(chave)]) - ord("A")
            if char.islower():
                resultado += chr((ord(char) - start - chave_offset) % 26 + start)
            else:
                resultado += chr((ord(char) - start - chave_offset) % 26 + start)
            chave_idx += 1
        else:
            resultado += char
    return resultado



def rc4_criptografar(texto, chave):
    # Key-Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    chave_bytes = [ord(c) for c in chave]
    for i in range(256):
        j = (j + S[i] + chave_bytes[i % len(chave_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    resultado = []
    for char in texto.encode("utf-8"):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        resultado.append(char ^ K)

    # Retorna como string de números decimais separados por espaço
    return " ".join(str(b) for b in resultado)


def rc4_descriptografar(decimal_texto, chave):
    # Converte de string decimal para lista de bytes
    texto_bytes = [int(x) for x in decimal_texto.split()]

    # Key-Scheduling Algorithm (KSA)
    S = list(range(256))
    j = 0
    chave_bytes = [ord(c) for c in chave]
    for i in range(256):
        j = (j + S[i] + chave_bytes[i % len(chave_bytes)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    resultado = []
    for char in texto_bytes:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        resultado.append(char ^ K)

    return bytes(resultado).decode("utf-8", errors="ignore")
