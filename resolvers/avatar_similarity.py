"""Avatar similarity scoring for identity disambiguation.

Uses perceptual average-hashing (Pillow only — no extra deps) as primary
method, with a Claude Haiku Vision fallback for inconclusive cases.

Context7 Pillow reference (from /python-pillow/pillow):
    from PIL import Image
    import io
    im = Image.open(io.BytesIO(buffer))

Algorithm:
    1. Resize image to 8x8 grayscale -> 64-pixel average hash (aHash)
    2. Compare two hashes by Hamming distance (0 = identical, 64 = opposite)
    3. distance <= 8  -> strong match (same or very similar image)
    4. distance >= 25 -> likely different image
    5. 8 < d < 25     -> inconclusive -> escalate to Claude Haiku Vision
"""

from __future__ import annotations

import base64
import io
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_PHASH_MATCH     = 8
_PHASH_MISMATCH  = 25
_VISION_MODEL    = "claude-haiku-4-5-20251001"
_FETCH_TIMEOUT   = 8


def fetch_image_bytes(url: str, timeout: int = _FETCH_TIMEOUT) -> bytes | None:
    """Download an image URL and return raw bytes. Returns None on any error."""
    if not url:
        return None
    try:
        resp = httpx.get(
            url,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; osint-recon/1.0)"},
        )
        if resp.status_code == 200 and resp.content:
            return resp.content
        logger.debug("fetch_image_bytes: HTTP %s for %s", resp.status_code, url)
    except Exception as exc:
        logger.debug("fetch_image_bytes failed for %s: %s", url, exc)
    return None


def _avg_hash(img_bytes: bytes) -> str | None:
    """Compute 64-bit average hash from image bytes using Pillow.

    Resize to 8x8 grayscale, compare each pixel to mean.
    Returns 64-char binary string or None on error.

    Context7 Pillow snippet:
        from PIL import Image; import io
        im = Image.open(io.BytesIO(buffer))
    """
    try:
        from PIL import Image  # type: ignore[import]
        img = (
            Image.open(io.BytesIO(img_bytes))
            .convert("L")
            .resize((8, 8), Image.LANCZOS)
        )
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        return "".join("1" if p > avg else "0" for p in pixels)
    except Exception as exc:
        logger.debug("_avg_hash failed: %s", exc)
        return None


def hamming_distance(hash_a: str, hash_b: str) -> int | None:
    """Hamming distance between two equal-length binary hash strings."""
    if not hash_a or not hash_b or len(hash_a) != len(hash_b):
        return None
    return sum(a != b for a, b in zip(hash_a, hash_b))


def _vision_compare(ref_bytes: bytes, candidate_bytes: bytes) -> float:
    """Ask Claude Haiku Vision if two profile pictures show the same person.

    Returns 0.0-1.0 confidence (0.5 = unknown/error).
    """
    try:
        from anthropic import Anthropic  # type: ignore[import]

        def _b64(b: bytes) -> str:
            return base64.standard_b64encode(b).decode()

        def _mime(b: bytes) -> str:
            if b[:3] == b"\xff\xd8\xff":
                return "image/jpeg"
            if b[:8] == b"\x89PNG\r\n\x1a\n":
                return "image/png"
            if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
                return "image/webp"
            return "image/jpeg"

        client = Anthropic()
        response = client.messages.create(
            model=_VISION_MODEL,
            max_tokens=10,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "Do these two profile pictures show the same person? "
                                "Reply with only a number 0-100 "
                                "(0=definitely different people, 100=definitely same person)."
                            ),
                        },
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": _mime(ref_bytes),
                                "data": _b64(ref_bytes),
                            },
                        },
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": _mime(candidate_bytes),
                                "data": _b64(candidate_bytes),
                            },
                        },
                    ],
                }
            ],
        )
        raw = response.content[0].text.strip()
        digits = "".join(c for c in raw if c.isdigit())
        score = int(digits[:3]) / 100.0 if digits else 0.5
        return min(1.0, max(0.0, score))

    except Exception as exc:
        logger.debug("_vision_compare failed: %s", exc)
        return 0.5


def score_avatar_match(ref_bytes: bytes, candidate_bytes: bytes) -> float:
    """Return 0.0-1.0 similarity between two avatar images.

    Pipeline:
    1. avg-hash both images
    2. dist <= 8  -> high score (no Vision call)
    3. dist >= 25 -> low score  (no Vision call)
    4. inconclusive -> Claude Haiku Vision
    5. hashing fails -> Vision directly
    """
    hash_a = _avg_hash(ref_bytes)
    hash_b = _avg_hash(candidate_bytes)

    if hash_a and hash_b:
        dist = hamming_distance(hash_a, hash_b)
        if dist is not None:
            if dist <= _PHASH_MATCH:
                score = 1.0 - dist / (_PHASH_MATCH * 2)
                logger.debug("Avatar pHash match: dist=%d score=%.2f", dist, score)
                return round(score, 3)
            if dist >= _PHASH_MISMATCH:
                score = max(0.0, 1.0 - dist / 64.0)
                logger.debug("Avatar pHash mismatch: dist=%d score=%.2f", dist, score)
                return round(score, 3)
            logger.debug("Avatar pHash inconclusive: dist=%d -> Vision", dist)

    score = _vision_compare(ref_bytes, candidate_bytes)
    logger.debug("Avatar Vision score: %.2f", score)
    return round(score, 3)
