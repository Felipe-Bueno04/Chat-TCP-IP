import unicodedata

def _normalize_text(text):
    # Remove acentos e converte em maiúsculas, substitui J -> I
    normalized = unicodedata.normalize('NFD', text)
    filtered = ''.join(c for c in normalized if c.isalpha())
    return filtered.upper().replace('J', 'I')

def _generate_key_matrix(key):
    key = _normalize_text(key)
    seen = set()
    seq = []
    for ch in key:
        if ch not in seen:
            seen.add(ch)
            seq.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # J omitido
        if ch not in seen:
            seen.add(ch)
            seq.append(ch)
    matrix = [seq[i*5:(i+1)*5] for i in range(5)]
    positions = {matrix[r][c]: (r, c) for r in range(5) for c in range(5)}
    return matrix, positions

def playfair_criptografar(text, key):
    """
    Criptografa preservando caracteres não-alfabéticos.
    Letras são normalizadas (acentos removidos, J->I) e criptografadas em digráfos.
    Não-alfabéticos (espaços, pontuação) são mantidos na saída.
    """
    matrix, pos = _generate_key_matrix(key)
    out = []
    i = 0
    n = len(text)
    while i < n:
        if not text[i].isalpha():
            out.append(text[i])
            i += 1
            continue

        # coletar bloco contínuo de letras (preserva limites por espaços/pontuação)
        j = i
        while j < n and text[j].isalpha():
            j += 1
        block = text[i:j]               # bloco com possíveis acentos/maiúsculas/minúsculas
        norm = _normalize_text(block)   # normaliza para A-Z (J->I)
        # construir digráfos com 'X' quando necessário
        k = 0
        digraphs = []
        while k < len(norm):
            a = norm[k]
            if k + 1 < len(norm):
                b = norm[k+1]
                if a == b:
                    digraphs.append(a + 'X')
                    k += 1
                else:
                    digraphs.append(a + b)
                    k += 2
            else:
                digraphs.append(a + 'X')
                k += 1

        # criptografa os digráfos e adiciona (sem inserir espaços)
        for dg in digraphs:
            a, b = dg[0], dg[1]
            ra, ca = pos[a]
            rb, cb = pos[b]
            if ra == rb:
                out.append(matrix[ra][(ca+1) % 5])
                out.append(matrix[rb][(cb+1) % 5])
            elif ca == cb:
                out.append(matrix[(ra+1) % 5][ca])
                out.append(matrix[(rb+1) % 5][cb])
            else:
                out.append(matrix[ra][cb])
                out.append(matrix[rb][ca])

        i = j  # pula para depois do bloco de letras

    return ''.join(out)


def playfair_descriptografar(cipher_text, key):
    """
    Descriptografa preservando caracteres não-alfabéticos.
    Espera que os blocos de letras venham como pares contínuos (sem espaços),
    e que não-alfabéticos estejam no lugar original (ex.: espaços).
    """
    matrix, pos = _generate_key_matrix(key)
    out = []
    i = 0
    n = len(cipher_text)
    while i < n:
        if not cipher_text[i].isalpha():
            out.append(cipher_text[i])
            i += 1
            continue

        # coletar bloco contínuo de letras cifradas
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
            if ra == rb:
                out.append(matrix[ra][(ca-1) % 5])
                out.append(matrix[rb][(cb-1) % 5])
            elif ca == cb:
                out.append(matrix[(ra-1) % 5][ca])
                out.append(matrix[(rb-1) % 5][cb])
            else:
                out.append(matrix[ra][cb])
                out.append(matrix[rb][ca])
            k += 2

        i = j

    return ''.join(out)