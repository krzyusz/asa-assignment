import os

# config.py now refuses to start without a strong SECRET_KEY (finding #3).
# Set a test-only key before the app modules are imported.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-production-use-1234567890")
