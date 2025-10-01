
def texto_para_bits(texto):
    return ''.join(format(ord(c), '08b') for c in texto)

def bits_para_texto(bits):
    return ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))

def hex_para_bits(hex_str):
    return ''.join(format(int(hex_str[i:i+2], 16), '08b') for i in range(0, len(hex_str), 2))

def bits_para_hex(bits):
    return ''.join(format(int(bits[i:i+4], 2), 'x') for i in range(0, len(bits), 4)).upper()

def permutar(bits, tabela):
    return ''.join(bits[i-1] for i in tabela)

def xor(a, b):
    return ''.join('1' if x != y else '0' for x,y in zip(a,b))


def gerar_sub_chaves(chave_bits):

def f(R, K):
    pass

def des_criptografar(mensagem, chave):
    try:
        bloco_64 = hex_para_bits(mensagem)
    except ValueError:
        bloco_64 = texto_para_bits(mensagem)

    chave_bits = hex_para_bits(chave)
    bloco_64 = permutar(bloco_64, IP)

    L, R = bloco_64[:32], bloco_64[32:]
    sub_chaves = gerar_sub_chaves(chave_bits)

    for i in range(16):
        L, R = R, xor(L, f(R, sub_chaves[i]))

    bloco_64 = R + L
    bloco_64 = permutar(bloco_64, IP_INV)
    return bits_para_hex(bloco_64)

def des_decifrar(cipher_hex, chave):
    bloco_64 = hex_para_bits(cipher_hex)
    chave_bits = hex_para_bits(chave)
    bloco_64 = permutar(bloco_64, IP)

    L, R = bloco_64[:32], bloco_64[32:]
    sub_chaves = gerar_sub_chaves(chave_bits)

    for i in range(15, -1, -1):
        L, R = R, xor(L, f(R, sub_chaves[i]))

    bloco_64 = R + L
    bloco_64 = permutar(bloco_64, IP_INV)
    return bits_para_texto(bloco_64)
