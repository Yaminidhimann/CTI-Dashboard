from flask import Flask, render_template, request, Response
from pymongo import MongoClient
import csv
import io

app = Flask(__name__)

# -------------------------------
# MongoDB Connection
# -------------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["cti_dashboard"]
collection = db["threat_data"]


# -------------------------------
# Helper Functions
# -------------------------------

# Categorize IOC (simple logic)
def categorize_indicator(indicator):
    ind = indicator.lower()

    if any(keyword in ind for keyword in ["malware", "trojan", "botnet"]):
        return "malicious"
    elif any(keyword in ind for keyword in ["suspicious", "unknown"]):
        return "suspicious"
    else:
        return "unknown"


# Detect Type (IP / URL / Domain)
def detect_type(indicator):
    indicator = indicator.strip()

    # If contains only digits and dots → IP
    if indicator.replace(".", "").isdigit():
        return "IP"

    # If it has forward slashes → URL
    if "/" in indicator:
        return "URL"

    # Else treat as domain
    return "Domain"


# -------------------------------
# Dashboard Route
# -------------------------------
@app.route("/")
def dashboard():
    query = request.args.get("query", "")

    # Search logic
    if query:
        raw_data = list(collection.find({
            "$or": [
                {"indicator": {"$regex": query, "$options": "i"}},
                {"type": {"$regex": query, "$options": "i"}},
                {"threat": {"$regex": query, "$options": "i"}}
            ]
        }))
    else:
        raw_data = list(collection.find())

    # Enrich data with category + detected type
    data = []
    for item in raw_data:
        indicator = item.get("indicator", "")

        item["category"] = categorize_indicator(indicator)
        item["detected_type"] = detect_type(indicator)

        data.append(item)

    return render_template("dashboard.html", data=data)


# -------------------------------
# Download as CSV Route
# -------------------------------
@app.route("/download")
def download_csv():
    raw_data = list(collection.find())

    output = io.StringIO()
    writer = csv.writer(output)

    # CSV Header
    writer.writerow(["Indicator", "Type", "Detected Type", "Category", "Threat", "Risk", "Date"])

    # Rows
    for item in raw_data:
        indicator = item.get("indicator", "")

        writer.writerow([
            indicator,
            item.get("type", ""),
            detect_type(indicator),
            categorize_indicator(indicator),
            item.get("threat", ""),
            item.get("risk", ""),
            item.get("date", "")
        ])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=threat_data.csv"}
    )


# -------------------------------
# Run the App
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
