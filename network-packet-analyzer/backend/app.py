"""Flask server: REST API for the packet analyzer plus the static dashboard."""

import csv
import io
import os

from flask import Flask, Response, jsonify, request, send_from_directory

from packet_capture import PacketCapture
from packet_store import PacketStore

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
store = PacketStore(max_packets=2000)
capture = PacketCapture(store)


def error(message, code=400):
    return jsonify({"error": message}), code


# ---------------------------------------------------------------- dashboard
@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


# ---------------------------------------------------------------------- API
@app.get("/api/interfaces")
def interfaces():
    return jsonify({"interfaces": capture.list_interfaces()})


@app.get("/api/capture/status")
def capture_status():
    return jsonify(capture.status())


@app.post("/api/capture/start")
def capture_start():
    body = request.get_json(silent=True) or {}
    try:
        capture.start(
            interface=body.get("interface"),
            bpf_filter=body.get("filter"),
            demo=bool(body.get("demo")),
        )
    except RuntimeError as exc:
        capture.error = str(exc)
        return error(str(exc), 400)
    return jsonify(capture.status())


@app.post("/api/capture/stop")
def capture_stop():
    capture.stop()
    return jsonify(capture.status())


@app.get("/api/packets")
def packets():
    try:
        limit = max(1, min(int(request.args.get("limit", 200)), 1000))
        after_id = max(0, int(request.args.get("after_id", 0)))
    except ValueError:
        return error("limit and after_id must be integers.")
    result = store.get_packets(
        limit=limit,
        protocol=request.args.get("protocol"),
        search=request.args.get("search"),
        after_id=after_id,
    )
    return jsonify({"packets": result, "count": len(result)})


@app.post("/api/packets/clear")
def packets_clear():
    store.clear()
    return jsonify({"cleared": True})


@app.get("/api/packets/export")
def packets_export():
    columns = ["id", "time", "src", "dst", "sport", "dport", "protocol", "transport", "length", "ttl", "flags", "info"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for pkt in reversed(store.get_packets(limit=1000)):
        writer.writerow(pkt)
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packets.csv"},
    )


@app.get("/api/stats")
def stats():
    return jsonify(store.stats())


if __name__ == "__main__":
    # threaded=True so the dashboard can poll while the sniffer runs.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
