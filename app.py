from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
import fitz
import uuid
from pathlib import Path

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = Path("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)


@app.route('/ping', methods=['GET'])
def ping():
    return "pong", 200 
 
 

@app.route("/")
def index():
    return jsonify({"status": "PDF Extractor API is running ✅"})

@app.route("/extract", methods=["POST"])
def extract():
    if "file" not in request.files:
        return jsonify({"error": "Nessun file ricevuto"}), 400

    file     = request.files["file"]
    from_p   = int(request.form.get("from_page", 1)) - 1
    to_p     = int(request.form.get("to_page", 1)) - 1
    out_name = request.form.get("output_name", "extracted").strip() or "extracted"

    if not file.filename.endswith(".pdf"):
        return jsonify({"error": "File non valido"}), 400

    uid      = uuid.uuid4().hex
    in_path  = UPLOAD_FOLDER / f"{uid}_input.pdf"
    out_path = UPLOAD_FOLDER / f"{uid}_{out_name}.pdf"

    file.save(in_path)

    try:
        src = fitz.open(str(in_path))

        if from_p < 0 or to_p >= src.page_count or from_p > to_p:
            count = src.page_count
            src.close()
            return jsonify({"error": f"Intervallo non valido (PDF ha {count} pagine)"}), 400

        out = fitz.open()
        out.insert_pdf(src, from_page=from_p, to_page=to_p)
        out.save(str(out_path))
        src.close()
        out.close()

        return send_file(
            str(out_path),
            as_attachment=True,
            download_name=f"{out_name}.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if in_path.exists():
            in_path.unlink()

if __name__ == "__main__":
    app.run(debug=True)
