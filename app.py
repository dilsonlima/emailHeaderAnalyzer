from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import email
from email import policy
from email.parser import BytesParser
import os

app = Flask(__name__, template_folder="templates")
CORS(app)

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Lista de palavras-chave suspeitas em anexos
PALAVRAS_SUSPEITAS = [
    "pagar", "fatura", "debito", "cheque", "faca pix", "urgente",
    "pagamento", "extrato de debitos"
]

def verificar_anexos(msg):
    """
    Verifica se há anexos suspeitos no e-mail com base nas linhas Content-Type,
    Content-Transfer-Encoding e Content-Disposition.
    """
    anexos_suspeitos = []

    for part in msg.walk():
        content_type = part.get_content_type()  # Verifica o tipo de conteúdo
        content_disposition = part.get("Content-Disposition")  # Verifica se é um anexo

        # Verifica se é um anexo PDF e contém uma palavra suspeita no nome
        if content_disposition and "attachment" in content_disposition.lower():
            filename = part.get_filename()
            if filename and filename.lower().endswith(".pdf"):  # Verifica se é um PDF
                if any(palavra in filename.lower() for palavra in PALAVRAS_SUSPEITAS):
                    anexos_suspeitos.append(filename)

    return anexos_suspeitos

# Lista de domínios suspeitos
DOMINIOS_SUSPEITOS = [
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.com.br"
]

import re

def extrair_email(remetente):
    """
    Extrai o endereço de e-mail do campo 'From', removendo nomes e caracteres extras.
    """
    match = re.search(r'<(.+?)>', remetente)
    if match:
        return match.group(1)  # Retorna o e-mail dentro de <>
    return remetente  # Se não houver <>, retorna o próprio remetente

def verificar_provedor(remetente):
    """
    Verifica se o remetente usa um provedor de pessoa física.
    """
    email_limpo = extrair_email(remetente)
    dominio = email_limpo.split("@")[-1] if "@" in email_limpo else ""
    
    return dominio in DOMINIOS_SUSPEITOS


def verificar_confiabilidade(cabecalho, remetente):
    """
    Verifica a confiabilidade do e-mail com base em múltiplos critérios,
    como SPF, DKIM e remetente.
    """
    # Extração correta do domínio do remetente
    if verificar_provedor(remetente):
        return False  # Se for um provedor suspeito, marca como não confiável

    # Verifica SPF e DKIM apenas se o remetente não for suspeito
    if "spf=pass" in cabecalho.lower() and "dkim=pass" in cabecalho.lower():
        return True

    # Outros critérios para classificar como spam
    if "x-spam-flag: yes" in cabecalho.lower():
        return False  # Marca como spam

    return False  # Por padrão, não é confiável


def analisar_cabecalho(email_bytes):
    """
    Analisa o cabeçalho do e-mail e retorna informações de confiabilidade.
    """
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)

    remetente = msg["From"] or "Desconhecido"
    destinatario = msg["To"] or "Desconhecido"
    assunto = msg["Subject"] or "Sem assunto"
    data = msg["Date"] or "Data não encontrada"

    cabecalho_completo = str(msg)

    confiavel = verificar_confiabilidade(cabecalho_completo, remetente)
    provedor_suspeito = verificar_provedor(remetente)
    anexos_suspeitos = verificar_anexos(msg)

    return {
        "remetente": remetente,
        "destinatario": destinatario,
        "assunto": assunto,
        "data": data,
        "confiavel": confiavel,
        "provedor_suspeito": provedor_suspeito,
        "anexos_suspeitos": anexos_suspeitos
    }
    
 
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Nome do arquivo inválido"}), 400

    if file:
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)

        with open(file_path, "rb") as f:
            email_bytes = f.read()

        resultado = analisar_cabecalho(email_bytes)

        return jsonify(resultado)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
