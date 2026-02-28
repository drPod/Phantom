"""Smoke-test for EntityExtractor on Modal GPU.

Run with:
    modal run inference/test_extractor.py
"""

from app import app
from inference.extractor import EntityExtractor


@app.local_entrypoint()
def main():
    extractor = EntityExtractor()
    result = extractor.extract_entities.remote(
        "Linus Torvalds. Email: torvalds@linux-foundation.org. "
        "GitHub: github.com/torvalds. Creator of Linux kernel and Git. "
        "Works at Linux Foundation."
    )
    print(result)
