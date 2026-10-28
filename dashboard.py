from flask import Flask, jsonify, render_template, request

from database import count_by_type, get_events, init_db

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/events")
def api_events():
    limit = request.args.get("limit", 50, type=int)
    limit = max(1, min(limit, 500))
    return jsonify(get_events(limit))


@app.route("/api/stats")
def api_stats():
    return jsonify(count_by_type())


if __name__ == "__main__":
    init_db()
    # 127.0.0.1 means only your own laptop can open it
    app.run(host="127.0.0.1", port=5000, debug=False)