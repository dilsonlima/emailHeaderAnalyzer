from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import email
from email import policy
from email.parser import BytesParser
import os

app = Flask(__name__, template_folder="templates")  # Define a pasta dos templates
CORS(app)

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def verificar_confiabilidade(cabecalho):
    return "spf=pass" in cabecalho.lower() and "dkim=pass" in cabecalho.lower()

def analisar_cabecalho(email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
    cabecalho_completo = str(msg)

    return {
        "remetente": msg["From"] or "Desconhecido",
        "destinatario": msg["To"] or "Desconhecido",
        "assunto": msg["Subject"] or "Sem assunto",
        "data": msg["Date"] or "Data não encontrada",
        "confiavel": verificar_confiabilidade(cabecalho_completo)
    }

@app.route("/")
def home():
    return render_template("index.html")  # Renderiza a página principal

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
    app.run(debug=True)
