from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import email
from email import policy
from email.parser import BytesParser
import os
import re

app = Flask(__name__, template_folder="templates")
CORS(app)

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Palavras-chave suspeitas em anexos
PALAVRAS_SUSPEITAS = [
    "pagar", "fatura", "debito", "cheque", "faca pix", "urgente",
    "pagamento", "extrato de debitos"
]

# Extensões de arquivos considerados perigosos
EXTENSOES_SUSPEITAS = [
    ".py", ".exe", ".tar", ".js", ".bat", ".sh", ".shell", ".java", ".javac", ".jar"
]

# Lista de domínios suspeitos (provedores de e-mails pessoais)
DOMINIOS_SUSPEITOS = [
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.com.br"
]


def extrair_email(remetente):
    """Extrai apenas o e-mail do remetente, ignorando o nome."""
    match = re.search(r'<(.+?)>', remetente)
    if match:
        return match.group(1)  # Retorna o e-mail dentro de <>
    return remetente  # Se não houver <>, retorna o próprio remetente


def verificar_provedor(remetente):
    """Verifica se o remetente usa um provedor de pessoa física."""
    email_limpo = extrair_email(remetente)
    dominio = email_limpo.split("@")[-1] if "@" in email_limpo else ""
    
    return dominio in DOMINIOS_SUSPEITOS


def verificar_anexos(msg):
    """Verifica se há anexos suspeitos no e-mail."""
    anexos_suspeitos = []

    for part in msg.walk():
        content_disposition = part.get("Content-Disposition")  # Verifica se é um anexo

        if content_disposition and "attachment" in content_disposition.lower():
            filename = part.get_filename()
            if filename:
                filename_lower = filename.lower()
                
                # Verifica palavras suspeitas no nome do arquivo
                if any(palavra in filename_lower for palavra in PALAVRAS_SUSPEITAS):
                    anexos_suspeitos.append(f"Arquivo suspeito: {filename} (palavra-chave suspeita)")
                
                # Verifica extensões perigosas
                if any(filename_lower.endswith(ext) for ext in EXTENSOES_SUSPEITAS):
                    anexos_suspeitos.append(f"Arquivo perigoso: {filename} (extensão proibida)")

    return anexos_suspeitos


def verificar_confiabilidade(cabecalho, remetente):
    """
    Verifica a confiabilidade do e-mail com base no remetente e nos registros SPF/DKIM.
    Retorna False e uma lista de motivos se for suspeito.
    """
    confiavel = True  # Por padrão, assume que o e-mail é confiável
    motivos = []

    # Verifica se o remetente usa um provedor suspeito
    if verificar_provedor(remetente):
        motivos.append("Remetente usa provedor de e-mail pessoal (ex: Gmail, Hotmail, Yahoo).")
        confiavel = False

    # Verifica SPF e DKIM
    if "spf=pass" not in cabecalho.lower() or "dkim=pass" not in cabecalho.lower():
        motivos.append("Falha na autenticação SPF/DKIM.")
        confiavel = False

    # Verifica se o e-mail tem marcação de spam nos cabeçalhos
    if "x-spam-flag: yes" in cabecalho.lower():
        motivos.append("Marcado como SPAM no cabeçalho do e-mail.")
        confiavel = False

    return confiavel, motivos  # Retorna confiabilidade e os motivos



def analisar_cabecalho(email_bytes):
    """Analisa o cabeçalho do e-mail e retorna informações detalhadas."""
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)

    remetente = msg["From"] or "Desconhecido"
    destinatario = msg["To"] or "Desconhecido"
    assunto = msg["Subject"] or "Sem assunto"
    data = msg["Date"] or "Data não encontrada"

    cabecalho_completo = str(msg)

    confiavel, motivos = verificar_confiabilidade(cabecalho_completo, remetente)
    anexos_suspeitos = verificar_anexos(msg)

    # Se houver anexos suspeitos, adicionamos os nomes dos arquivos à lista de motivos
    if anexos_suspeitos:
        motivos.append(f"Contém anexos suspeitos: {', '.join(anexos_suspeitos)}")
        confiavel = False  # Se houver anexos suspeitos, o e-mail não pode ser confiável

    return {
        "remetente": remetente,
        "destinatario": destinatario,
        "assunto": assunto,
        "data": data,
        "confiavel": confiavel,
        "motivos": motivos if motivos else ["Nenhuma ameaça detectada."]
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

        return jsonify(resultado)  # Retornando corretamente o JSON



if __name__ == "__main__":
    app.run(debug=True, port=5002)
