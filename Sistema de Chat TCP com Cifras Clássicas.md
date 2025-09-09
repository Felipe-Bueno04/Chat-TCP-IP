# Sistema de Chat TCP com Cifras Clássicas

## Arquivos do Sistema
- `servidor.py` - Servidor TCP que gerencia as conexões e mensagens
- `cliente.py` - Cliente TCP com interface para escolha de cifra e chave
- `cifras.py` - Implementação das quatro cifras clássicas

## Como Usar

### 1. Iniciar o Servidor
```bash
python3 servidor.py
```
O servidor ficará escutando na porta 5000 e aceitará conexões de qualquer IP.

### 2. Conectar Clientes
```bash
python3 cliente.py
```

### 3. Configuração do Cliente
1. **Digite o IP do servidor** - Insira o endereço IP do servidor ao qual deseja se conectar
2. **Escolha a cifra** - Selecione uma das quatro opções:
   - 1. Cifra de César
   - 2. Substituição Monoalfabética
   - 3. Cifra de Playfair
   - 4. Cifra de Vigenère
3. **Defina a chave secreta** - Insira a chave conforme o tipo de cifra escolhida

### 4. Tipos de Chaves por Cifra

#### Cifra de César
- **Chave**: Número inteiro (ex: 3)
- **Exemplo**: Chave 3 transforma "ABC" em "DEF"

#### Substituição Monoalfabética
- **Chave**: Alfabeto embaralhado de 26 letras únicas
- **Exemplo**: "QWERTYUIOPASDFGHJKLZXCVBNM"

#### Cifra de Playfair
- **Chave**: Palavra ou frase (ex: "KEYWORD")
- **Observação**: J é tratado como I

#### Cifra de Vigenère
- **Chave**: Palavra ou frase (ex: "LEMON")
- **Observação**: A chave se repete conforme necessário

### 5. Envio de Mensagens
- Digite sua mensagem e pressione Enter
- A mensagem será criptografada antes do envio
- Outros clientes receberão a mensagem descriptografada automaticamente
- Digite "flw" para sair do chat

### 6. Depuração no Servidor
O servidor imprime no console todas as mensagens criptografadas recebidas para facilitar a conferência e depuração.

## Funcionalidades Implementadas
✅ Conexão TCP entre múltiplos clientes e servidor
✅ Menu de escolha de cifra
✅ Validação de chaves por tipo de cifra
✅ Criptografia automática antes do envio
✅ Descriptografia automática no recebimento
✅ Exibição de mensagens criptografadas e descriptografadas
✅ Log de mensagens no servidor para depuração
✅ Suporte a caracteres especiais e espaços
✅ Tratamento de erros de conexão

## Observações Técnicas
- O servidor aceita conexões de qualquer IP (0.0.0.0)
- Porta padrão: 5000
- Encoding: UTF-8
- Threads separadas para recebimento de mensagens
- Validação de entrada para chaves de cifra

