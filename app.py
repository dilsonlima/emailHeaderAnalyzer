from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import email
from email import policy
from email.parser import BytesParser
import os
import re
from datetime import datetime
import pytz
import dkim
import spf

app = Flask(__name__, template_folder="templates")
CORS(app)

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Palavras-chave suspeitas em anexos
PALAVRAS_SUSPEITAS = [
    "pagar", "fatura", "debito", "cheque", "pix", "urgente",
    "pagamento", "boleto", "extrato", "2º via", 
    "cobranca", "cobrança", "2", "segunda"
]

# Extensões de arquivos considerados perigosos 
EXTENSOES_SUSPEITAS = [
    ".py", ".exe", ".tar", ".js", ".bat", ".sh", ".shell", ".java", ".javac", ".jar",
    ".dll", ".ini", ".zip", ".gz", ".zip", ".rar", ".bot", ".boot", ".c",
    "ade", "adp", "chm", "cmd", "com", "cpl", "hta", "ins", "isp", "jse", "lib", "lnk",
    "mde", "msc", "msp", "mst", "pif", "scr", "sct", "shb", "sys", "vb",
    "vbe", "vbs", "vxd", "wsc", "wsf", "wsh"
]

# Lista de domínios suspeitos (provedores de e-mails pessoais)
DOMINIOS_SUSPEITOS = [
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", 
    "yahoo.com.br", "globo.com", "bol.com.br", "uol.com.br", 
    "live.com", "outlook.com.br", "ig.com.br", "zoho.com", 
    "zoho.com.br", "icloud.com", "icloud.com.br", "proton.com", 
    "protonmail.com", "proton.me", "aol.com.br", "aol.com"
]

def extrair_email(remetente):
    """Extrai apenas o e-mail do remetente, ignorando o nome."""
    match = re.search(r'<(.+?)>', remetente)
    if match:
        return match.group(1)  # Retorna o e-mail dentro de <>
    return remetente  # Se não houver <>, retorna o próprio remetente

def extrair_emails_cabecalho(cabecalho):
    """Extrai emails relevantes do cabeçalho."""
    return_path = re.search(r"Return-Path: <(.+?)>", cabecalho, re.IGNORECASE)
    remetente_smtp = re.search(r"smtp\.mailfrom=(.+)", cabecalho, re.IGNORECASE)

    return {
        "return_path": return_path.group(1) if return_path else None,
        "remetente_smtp": remetente_smtp.group(1) if remetente_smtp else None,
    }

def verificar_provedor(remetente):
    """Verifica se o remetente usa um provedor de pessoa física."""
    email_limpo = extrair_email(remetente)
    dominio = email_limpo.split("@")[-1] if "@" in email_limpo else ""
    
    return dominio in DOMINIOS_SUSPEITOS

def verificar_autenticacao(cabecalho):
    """Verifica SPF, DKIM e DMARC."""
    spf_resultado = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", cabecalho, re.IGNORECASE)
    dkim_resultado = re.search(r"dkim=(pass|fail|neutral|none|temperror|permerror)", cabecalho, re.IGNORECASE)
    dmarc_resultado = re.search(r"dmarc=(pass|fail|neutral|none|temperror|permerror)", cabecalho, re.IGNORECASE)

    return {
        "spf": spf_resultado.group(1) if spf_resultado else None,
        "dkim": dkim_resultado.group(1) if dkim_resultado else None,
        "dmarc": dmarc_resultado.group(1) if dmarc_resultado else None,
    }

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

def verificar_fuso_horario(data_email):
    """
    Verifica se o fuso horário do e-mail está muito diferente do esperado.
    Retorna True se for suspeito.
    """
    try:
        match = re.search(r"([+-]\d{4})", data_email)  # Captura algo como +0100, -0300, etc.
        if match:
            fuso_str = match.group(1)
            horas_offset = int(fuso_str[:3])  # Extrai horas (ex: -03 de -0300)

            # Fuso horário do e-mail
            fuso_email = pytz.FixedOffset(horas_offset * 60)

            # Fuso atual do sistema
            agora = datetime.now(FUSO_ESPERADO)
            agora_email = agora.astimezone(fuso_email)

            diferenca = abs(agora.utcoffset().total_seconds() - agora_email.utcoffset().total_seconds()) / 3600

            return diferenca > 3  # Se a diferença for maior que 3 horas, marca como suspeito
    except Exception:
        pass

    return False

def verificar_confiabilidade(cabecalho, remetente, anexos_suspeitos, fuso_horario_suspeito):
    """
    Verifica a confiabilidade do e-mail considerando múltiplos critérios e retorna os motivos de bloqueio.
    """
    motivos_bloqueio = []

    # Se o remetente for de um provedor suspeito, adiciona motivo
    if verificar_provedor(remetente):
        motivos_bloqueio.append("O remetente usa um provedor de e-mail de pessoa física.")

    # Se houver anexos suspeitos, adiciona motivo
    if anexos_suspeitos:
        motivos_bloqueio.append(f"Anexos suspeitos encontrados: {', '.join(anexos_suspeitos)}")

    # Se o fuso horário for suspeito, adiciona motivo
    if fuso_horario_suspeito:
        motivos_bloqueio.append("O fuso horário do e-mail difere do fuso horário esperado.")

    # Se SPF ou DKIM falharem, adiciona motivo
    if "spf=fail" in cabecalho.lower() or "dkim=fail" in cabecalho.lower():
        motivos_bloqueio.append("Falha na verificação SPF ou DKIM.")

    # Se o cabeçalho indicar spam, adiciona motivo
    if "x-spam-flag: yes" in cabecalho.lower():
        motivos_bloqueio.append("O e-mail foi marcado como SPAM pelo servidor.")

    # Se houver qualquer motivo de bloqueio, o e-mail NÃO é confiável
    confiavel = len(motivos_bloqueio) == 0

    return confiavel, motivos_bloqueio

def analisar_cabecalho(email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    cabecalho_completo = str(msg)

    emails = extrair_emails_cabecalho(cabecalho_completo)
    autenticacao = verificar_autenticacao(cabecalho_completo)

    remetente = msg["From"] or "Desconhecido"
    destinatario = msg["To"] or "Desconhecido"
    assunto = msg["Subject"] or "Sem assunto"
    data = msg["Date"] or "Data não encontrada"

    cabecalho_completo = str(msg)

    # Extrair o domínio do remetente
    email_limpo = extrair_email(remetente)
    dominio = email_limpo.split("@")[-1] if "@" in email_limpo else ""

    # Consultar WHOIS do domínio
    whois_info = consultar_whois(dominio)

    # Extrair o IP do cabeçalho (exemplo simplificado)
    ip_match = re.search(r"Received: from (.+?) \(", cabecalho_completo)
    ip = ip_match.group(1) if ip_match else ""

    # Geolocalizar o IP
    geo_info = geolocalizar_ip(ip)

    # Definição correta das variáveis antes do uso
    anexos_suspeitos = verificar_anexos(msg)
    fuso_suspeito = verificar_fuso_horario(data)
    provedor_suspeito = verificar_provedor(remetente)

    # Agora chamamos a função corretamente
    confiavel, motivos = verificar_confiabilidade(
        cabecalho_completo, remetente, anexos_suspeitos, fuso_suspeito
    )

    return {
        "remetente": remetente,
        "destinatario": destinatario,
        "assunto": assunto,
        "data": data,
        "confiavel": confiavel,
        "provedor_suspeito": provedor_suspeito,
        "anexos_suspeitos": anexos_suspeitos,
        "fuso_suspeito": fuso_suspeito,
        "motivos": motivos,
        "emails": emails,
        "autenticacao": autenticacao, 
        "whois_info": whois_info,
        "geo_info": geo_info,
    }

#função whois
import whois

def consultar_whois(dominio):
    try:
        w = whois.whois(dominio)
        return {
            "nome": w.name,
            "email": w.email,
            "telefone": w.phone,
            "data_registro": w.creation_date,
            "data_expiracao": w.expiration_date,
            "status": w.status,
        }
    except Exception as e:
        return {"erro": str(e)}
    
    #funcao ipinfo.io
import requests

def geolocalizar_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            "ip": data.get("ip"),
            "cidade": data.get("city"),
            "regiao": data.get("region"),
            "pais": data.get("country"),
            "provedor": data.get("org"),
        }
    except Exception as e:
        return {"erro": str(e)}


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