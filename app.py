import re

def parse_email_header(header_text):
    """Analisa o cabeçalho de um e-mail e extrai informações importantes."""
    
    email_info = {
        "From": None,
        "To": None,
        "Subject": None,
        "Date": None,
        "Received": []
    }

    # Expressões regulares para extrair informações
    patterns = {
        "From": r"^From:\s*(.+)",
        "To": r"^To:\s*(.+)",
        "Subject": r"^Subject:\s*(.+)",
        "Date": r"^Date:\s*(.+)",
        "Received": r"^Received:\s*(.+)"
    }

    for line in header_text.split("\n"):
        line = line.strip()
        for key, pattern in patterns.items():
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                if key == "Received":
                    email_info[key].append(match.group(1))  # Pode haver múltiplos "Received"
                else:
                    email_info[key] = match.group(1)
    
    return email_info

def main():
    # Caminho do arquivo contendo o cabeçalho do e-mail
    file_path = input("Digite o caminho do arquivo de cabeçalho de e-mail: ")

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            header_text = file.read()
        
        email_data = parse_email_header(header_text)

        # Exibe os resultados
        print("\n📩 Informações do E-mail 📩")
        print(f"De: {email_data['From']}")
        print(f"Para: {email_data['To']}")
        print(f"Assunto: {email_data['Subject']}")
        print(f"Data: {email_data['Date']}")
        
        print("\n🔍 Servidores pelos quais o e-mail passou:")
        for received in email_data["Received"]:
            print(f" - {received}")

    except FileNotFoundError:
        print("❌ Arquivo não encontrado. Verifique o caminho e tente novamente.")

if __name__ == "__main__":
    main()
