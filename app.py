import email
from email import policy
from email.parser import BytesParser

# Função para analisar o cabeçalho do e-mail
def analisar_cabecalho(email_bytes):
    # Parse do e-mail usando a política padrão
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    
    # Extração das informações do cabeçalho
    remetente = msg['From']
    destinatario = msg['To']
    assunto = msg['Subject']
    data = msg['Date']
    message_id = msg['Message-ID']
    
    print("Remetente:", remetente)
    print("Destinatário:", destinatario)
    print("Assunto:", assunto)
    print("Data:", data)
    print("Message-ID:", message_id)

# Exemplo de como você pode usar a função
if __name__ == "__main__":
    # O arquivo de e-mail é um exemplo, substitua pelo caminho do e-mail que deseja analisar
    arquivo_email = 'caminho do arquivo/email.eml'  # Insira o caminho correto para o arquivo .eml
    
    # Lê o arquivo de e-mail
    with open(arquivo_email, 'rb') as f:
        email_bytes = f.read()
        
    # Chama a função para analisar o cabeçalho
    analisar_cabecalho(email_bytes)
