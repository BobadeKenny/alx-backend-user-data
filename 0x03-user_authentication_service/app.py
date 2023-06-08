#!/usr/bin/env python3
"""Basic Flask app"""
from flask import Flask, jsonify, request, abort, redirect


app = Flask(__name__)


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """GET /
    Return:
      - the status of the API
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run()
