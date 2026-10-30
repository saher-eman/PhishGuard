from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello, PhishGuard!"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Call the compiled C++ program, passing the URL as a command-line argument
    result = subprocess.run(
        ["analyzer.exe", url],
        capture_output=True,
        text=True
    )

    # Extract just the JSON part from the C++ program's full printed output
    output = result.stdout
    json_start = output.find("{")
    json_text = output[json_start:]

    analysis = json.loads(json_text)

    return jsonify(analysis)

if __name__ == "__main__":
    app.run(debug=True)
