"""
Lab 11 — Configuration & API Key Setup
"""
import os
from pathlib import Path

from dotenv import load_dotenv


def setup_api_key():
    """Load Google API key from environment or prompt."""
    repo_root = Path(__file__).resolve().parents[2]
    load_dotenv(repo_root / ".env")
    load_dotenv()

    api_key = os.environ.get("GOOGLE_API_KEY", "").strip().strip('"').strip("'")
    if not api_key:
        api_key = input("Enter Google API Key: ").strip().strip('"').strip("'")
    os.environ["GOOGLE_API_KEY"] = api_key
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print("API key loaded.")


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
