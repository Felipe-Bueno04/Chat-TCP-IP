# ---------------- CIFRA DE CÉSAR ---------------- #
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


# ---------------- CIFRA SUBSTITUIÇÃO MONOALFABÉTICA ---------------- #
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


# ---------------- CIFRA PLAYFAIR ---------------- #
import unicodedata # Biblioteca usada para normalizar strings e remover acentos

def _normalize_text(text): # Função que normaliza o texto:
    
    # - Remove acentos
    # - Deixa todas as letras maiúsculas
    # - Substitui J por I (regra da cifra Playfair)
    normalized = unicodedata.normalize('NFD', text)
    filtered = ''.join(c for c in normalized if c.isalpha())
    print(filtered.upper().replace('J', 'I'))
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
    for row in matrix:
        print(row)

    # Dicionário que guarda a posição (linha, coluna) de cada letra
    positions = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    return matrix, positions

def _make_digraphs(norm):
    digraphs = []
    i = 0
    while i < len(norm):
        a = norm[i]
        if i + 1 < len(norm):
            b = norm[i+1]
            if a == b:  # Letras iguais → insere 'X' depois da primeira
                digraphs.append(a + 'X')
                i += 1
            else:
                digraphs.append(a + b)
                i += 2
        else:
            # Última letra sozinha → adiciona X
            digraphs.append(a + 'X')
            i += 1
    return digraphs

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
        digraphs = _make_digraphs(norm)

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

    # Quebra a string em pares de 2 e junta com espaço
    cipher_text = ''.join(out)
    pairs = [cipher_text[i:i+2] for i in range(0, len(cipher_text), 2)]
    return ''.join(pairs)

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


# ---------------- CIFRA VIGENERE ---------------- #
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


# ---------------- CIFRA RC4 ---------------- #
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


# ---------------- CIFRA DES ---------------- #

# Permutação inicial
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Permutação final
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansão de 32 para 48 bits
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutação P dentro da função F
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# Permutação PC1 (chave inicial → 56 bits)
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 
    58, 50, 42, 34, 26, 18, 10, 2, 
    59, 51, 43, 35, 27, 19, 11, 3, 
    60, 52, 44, 36,63, 55, 47, 39, 
    31, 23, 15, 7, 62, 54, 46, 38, 
    30, 22, 14, 6, 61, 53, 45, 37, 
    29, 21, 13, 5, 28, 20, 12, 4
]

# Permutação PC2 (56 bits → 48 bits)
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 
    15, 6, 21, 10, 23, 19, 12, 4, 
    26, 8, 16, 7, 27, 20, 13, 2, 
    41, 52, 31, 37, 47, 55, 30, 40, 
    51, 45, 33, 48, 44, 49, 39, 56, 
    34, 53, 46, 42, 50, 36, 29, 32
]

# Número de shifts por rodada
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-Boxes (8 tabelas)
SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# ---------------- Funções auxiliares ---------------- #

def texto_para_bits(texto):
    """Converte texto para string de bits"""
    bits = ''
    for char in texto:
        bits += format(ord(char), '08b')
    return bits

def bits_para_texto(bits):
    """Converte string de bits para texto"""
    texto = ''
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            texto += chr(int(byte, 2))
    return texto

def hex_para_bits(hex_string):
    """Converte hexadecimal para bits"""
    return bin(int(hex_string, 16))[2:].zfill(64)

def bits_para_hex(bits):
    """Converte bits para hexadecimal"""
    return hex(int(bits, 2))[2:].upper().zfill(16)

def permutar(bits, tabela):
    """Aplica permutação usando a tabela fornecida"""
    return ''.join(bits[i-1] for i in tabela)

def xor(a, b):
    """Operação XOR entre duas strings de bits"""
    return ''.join('1' if bit_a != bit_b else '0' for bit_a, bit_b in zip(a, b))

def left_shift(bits, n):
    """Deslocamento circular para esquerda"""
    return bits[n:] + bits[:n]

def adicionar_padding(texto):
    """Adiciona padding PKCS#7"""
    padding_len = 8 - (len(texto) % 8)
    if padding_len == 0:
        padding_len = 8  # ← ISSO ESTÁ CORRETO
    
    # Padding com o valor do tamanho do padding
    padding = chr(padding_len) * padding_len
    padded_text = texto + padding
    
    print(f"DEBUG Padding: texto '{texto}' -> '{padded_text}' (padding: {padding_len})")
    return padded_text

def remover_padding(texto):
    """Remove padding PKCS#7 de forma robusta"""
    if len(texto) == 0:
        return texto
    
    # Último byte indica quantos bytes de padding há
    last_byte = texto[-1]
    if isinstance(last_byte, str):
        padding_len = ord(last_byte)
    else:
        padding_len = last_byte
    
    print(f"DEBUG Remover Padding: último byte={padding_len}, texto length={len(texto)}")
    
    # Verifica se o padding é válido (1-8)
    if padding_len < 1 or padding_len > 8:
        print(f"DEBUG: Padding inválido {padding_len}, retornando texto original")
        return texto
    
    # Verifica se temos bytes suficientes
    if len(texto) < padding_len:
        print(f"DEBUG: Texto muito curto para padding {padding_len}")
        return texto
    
    # Verifica se os últimos 'padding_len' bytes são iguais ao valor do padding
    expected_padding = chr(padding_len) * padding_len
    if texto[-padding_len:] == expected_padding:
        return texto[:-padding_len]
    else:
        print(f"DEBUG: Padding inconsistente")
        # Tenta remover apenas se os últimos bytes forem caracteres de controle
        if all(ord(c) < 32 for c in texto[-padding_len:]):
            return texto[:-padding_len]
        else:
            return texto

# ---------------- Função F ---------------- #
def funcao_f(R, K):
    """Função F do DES com debug"""
    # Expansão de 32 para 48 bits
    R_expandido = permutar(R, E)
    
    # XOR com a subchave
    xor_result = xor(R_expandido, K)
    
    # Debug detalhado
    debug_detalhado = False
    
    # Aplica S-Boxes
    sbox_saida = ''
    sbox_debug = []
    for i in range(8):
        bloco_6bits = xor_result[i*6:(i+1)*6]
        linha = int(bloco_6bits[0] + bloco_6bits[5], 2)
        coluna = int(bloco_6bits[1:5], 2)
        valor_sbox = SBOXES[i][linha][coluna]
        sbox_saida += format(valor_sbox, '04b')
        sbox_debug.append((i, bloco_6bits, linha, coluna, valor_sbox))
    
    # Permutação final
    resultado = permutar(sbox_saida, P)
    
    return resultado

# ---------------- Geração de subchaves ---------------- #
def gerar_subchaves(chave_64bits):
    """Gera as 16 subchaves do DES"""
    # Permutação PC1
    chave_56bits = permutar(chave_64bits, PC1)
    
    C = chave_56bits[:28]
    D = chave_56bits[28:]
    
    subchaves = []
    
    for rodada in range(16):
        # Deslocamento circular
        C = left_shift(C, SHIFTS[rodada])
        D = left_shift(D, SHIFTS[rodada])
        
        # Combina e aplica PC2
        chave_56_shifted = C + D
        subchave = permutar(chave_56_shifted, PC2)
        subchaves.append(subchave)
        
        # Formata em grupos de 6 bits
        k_formatted = ' '.join([subchave[i:i+6] for i in range(0, 48, 6)])
    
    return subchaves

# ---------------- Processamento de bloco ---------------- #

# Contador para saber qual bloco está processando
contador_bloco = 0

def processar_bloco_des(bloco_64bits, subchaves, modo='criptografar'):
    # Permutação inicial
    bloco = permutar(bloco_64bits, IP)
    
    L = bloco[:32]
    R = bloco[32:]
    
    if modo == 'criptografar':
        # 16 rodadas normais
        for i in range(16):
            L_novo = R
            R_novo = xor(L, funcao_f(R, subchaves[i]))
            L, R = L_novo, R_novo
        
        bloco_final = L + R  # ← L e R na mesma ordem, sem trocar
    
    else:
        # 16 rodadas inversas para descriptografia
        for i in range(15, -1, -1):
            R_novo = L
            L_novo = xor(R, funcao_f(L, subchaves[i]))
            L, R = L_novo, R_novo
        
        bloco_final = L + R
    
    # Permutação final
    return permutar(bloco_final, FP)

# ---------------- Interface principal ---------------- #
def des_criptografar(texto, chave):
    """Criptografa texto usando DES"""
    global contador_bloco
    contador_bloco = 0  # Reseta o contador a cada nova mensagem
    
    # Se a chave está em hexadecimal, converte para bits
    if all(c in '0123456789ABCDEFabcdef' for c in chave.replace(' ', '')) and len(chave.replace(' ', '')) == 16:
        # Chave em hexadecimal
        chave_hex = chave.replace(' ', '').upper()
        chave_bits = hex_para_bits(chave_hex)
    else:
        # Chave em texto (usa os primeiros 8 caracteres)
        chave_completa = chave.ljust(8, '\0')[:8]
        chave_bits = texto_para_bits(chave_completa)
    
    # Gera subchaves
    subchaves = gerar_subchaves(chave_bits)
    
    # Adiciona padding ao texto
    texto_com_padding = adicionar_padding(texto)
    
    # Converte texto para bits
    texto_bits = texto_para_bits(texto_com_padding)
    
    # Processa em blocos de 64 bits
    texto_criptografado_bits = ''
    for i in range(0, len(texto_bits), 64):
        bloco = texto_bits[i:i+64].ljust(64, '0')
        bloco_criptografado = processar_bloco_des(bloco, subchaves, 'criptografar')
        texto_criptografado_bits += bloco_criptografado
    
    # Converte bits para hexadecimal
    texto_hex = ''
    for i in range(0, len(texto_criptografado_bits), 8):
        byte = texto_criptografado_bits[i:i+8]
        texto_hex += format(int(byte, 2), '02X')
    
    return texto_hex

def des_descriptografar(texto_criptografado, chave):
    global contador_bloco
    contador_bloco = 0
    
    if all(c in '0123456789ABCDEFabcdef' for c in chave.replace(' ', '')) and len(chave.replace(' ', '')) == 16:
        # Chave em hexadecimal
        chave_hex = chave.replace(' ', '').upper()
        chave_bits = hex_para_bits(chave_hex)
    else:
        # Chave em texto (usa os primeiros 8 caracteres)
        chave_completa = chave.ljust(8, '\0')[:8]
        chave_bits = texto_para_bits(chave_completa)
    
    # Gera subchaves
    subchaves = gerar_subchaves(chave_bits)
    
    # Converte hexadecimal para bits
    texto_bits = ''
    for i in range(0, len(texto_criptografado), 2):
        byte_hex = texto_criptografado[i:i+2]
        byte_bin = format(int(byte_hex, 16), '08b')
        texto_bits += byte_bin
    
    # Processa em blocos de 64 bits
    texto_descriptografado_bits = ''
    for i in range(0, len(texto_bits), 64):
        if i + 64 <= len(texto_bits):
            bloco = texto_bits[i:i+64]
            bloco_descriptografado = processar_bloco_des(bloco, subchaves, 'descriptografar')
            texto_descriptografado_bits += bloco_descriptografado
    
    # Converte bits para texto
    texto_original = bits_para_texto(texto_descriptografado_bits)
    
    # Remove padding
    texto_final = remover_padding(texto_original)
    
    return texto_final

# Aliases para compatibilidade com código do amigo
def des_decifrar(texto_criptografado, chave):
    """Alias para des_descriptografar - compatível com código do amigo"""
    return des_descriptografar(texto_criptografado, chave)

def teste_com_padding_correto():
    """Teste com texto que precisa de padding"""
    print("=== TESTE COM PADDING ===")
    
    texto = "Atacar base norte."
    chave = "0123456789ABCDEF"
    
    print(f"Texto original: '{texto}'")
    print(f"Tamanho: {len(texto)} caracteres")
    
    # Mostrar o padding
    texto_com_padding = adicionar_padding(texto)
    print(f"Texto com padding: {[ord(c) for c in texto_com_padding]}")
    
    # Criptografar e descriptografar
    cifrado = des_criptografar(texto, chave)
    print(f"Cifrado (hex): {cifrado}")
    
    decifrado = des_descriptografar(cifrado, chave)
    print(f"Decifrado: '{decifrado}'")
    print(f"Sucesso: {decifrado == texto}")

teste_com_padding_correto()