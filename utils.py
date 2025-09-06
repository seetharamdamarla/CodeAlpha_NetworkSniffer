import csv
import datetime

def save_packets_to_csv(filepath, columns, data):
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        for row in data:
            writer.writerow([f"[{str(value)}]" for value in row])

def generate_filename(base_name="packets", extension="csv"):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"{base_name}_{current_time}.{extension}"

def format_payload(payload):
    try:
        if isinstance(payload, bytes):
            payload = payload.decode(errors="replace")
        return payload[:50] + "..." if len(payload) > 50 else payload
    except:
        return "<Binary Data>"
