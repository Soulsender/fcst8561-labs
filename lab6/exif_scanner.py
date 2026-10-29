
import csv
import base64
import re
from pathlib import Path
from PIL import Image

image_dir = Path(__file__).resolve().parent / "Images"
results = []

keywords = [
    "persist",
    "recon",
    "lateral",
    "exploit",
    "vuln",
    "exfil",
]


def clean_metadata(value):
    if isinstance(value, bytes):
        strings = re.findall(rb"[ -~]{4,}", value)
        return " ".join(s.decode("ascii") for s in strings)
    return str(value)


for path in sorted(image_dir.glob("*.png")):
    with Image.open(path) as img:
        metadata = img.info
        findings = []
        encodings = []
        reasons = []
        risk_score = 0

        for field, value in metadata.items():
            text = clean_metadata(value).strip()

            if any(word in text.lower() for word in keywords):
                findings.append(f"{field}: {text}")
                reasons.append("Suspicious text found")
                risk_score = max(risk_score, 50)

            # Detect Base64 and inspect decoded text
            for match in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
                try:
                    decoded = base64.b64decode(match, validate=True)
                    decoded_text = decoded.decode("utf-8").strip()

                    if decoded_text and decoded_text.isprintable():
                        findings.append(
                            f"{field}: decoded text: {decoded_text}"
                        )
                        encodings.append("Base64")
                        reasons.append("Base64-encoded text detected")
                        risk_score = max(risk_score, 40)

                        if any(
                            word in decoded_text.lower()
                            for word in keywords
                        ):
                            reasons.append(
                                "Suspicious keyword in decoded text"
                            )
                            risk_score = max(risk_score, 50)

                except (ValueError, UnicodeDecodeError):
                    pass

        results.append({
            "filename": path.name,
            "format": img.format,
            "metadata_fields": ", ".join(metadata.keys()),
            "suspected_field": "; ".join(findings),
            "encoding": ", ".join(sorted(set(encodings))) or "Plain text",
            "risk_score": risk_score,
            "reason": "; ".join(sorted(set(reasons)))
                      or "No suspicious indicators found",
        })

fields = [
    "filename",
    "format",
    "metadata_fields",
    "suspected_field",
    "encoding",
    "risk_score",
    "reason",
]

csv_file = Path(__file__).resolve().parent / "metadata_report.csv"
with open(csv_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(results)

print(f"Scanned {len(results)} images.")
