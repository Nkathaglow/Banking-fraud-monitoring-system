"""Run right after training, whenever models/*.pkl change:
    MODEL_MANIFEST_KEY=... python -m scripts.sign_models [models_dir]"""
import os
import sys

from src.model_service import write_manifest

key = os.environ.get("MODEL_MANIFEST_KEY", "")
if len(key) < 32:
    sys.exit("MODEL_MANIFEST_KEY must be set (>= 32 chars)")
models_dir = sys.argv[1] if len(sys.argv) > 1 else "models"
print(write_manifest(models_dir, key.encode()))
