import base64
import hashlib
import hmac
import io
from typing import Dict, Any, Optional

from datetime import datetime

# --- Micro-bounty Verification Badge Generator ---

def generate_verification_badge_svg(
    username: str,
    bounty_id: int,
    verified_at: Optional[datetime] = None,
    badge_color: str = "#4CAF50"
) -> str:
    """
    Generate an SVG badge for micro-bounty verification.

    Args:
        username (str): The username of the verified user.
        bounty_id (int): The bounty ID.
        verified_at (Optional[datetime]): The datetime of verification.
        badge_color (str): The color of the badge.

    Returns:
        str: SVG string representing the badge.
    """
    verified_str = (
        verified_at.strftime("%Y-%m-%d %H:%M UTC") if verified_at else "Verified"
    )
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="320" height="80">
  <rect rx="12" width="320" height="80" fill="{badge_color}"/>
  <text x="160" y="32" text-anchor="middle" font-size="24" fill="#fff" font-family="Arial, sans-serif" font-weight="bold">
    Micro-bounty Verified
  </text>
  <text x="160" y="54" text-anchor="middle" font-size="16" fill="#fff" font-family="Arial, sans-serif">
    @{username} for Bounty #{bounty_id}
  </text>
  <text x="160" y="70" text-anchor="middle" font-size="12" fill="#fff" font-family="Arial, sans-serif">
    {verified_str}
  </text>
</svg>'''
    return svg

def badge_svg_to_base64(svg: str) -> str:
    """
    Encode SVG string to base64 data URI.

    Args:
        svg (str): SVG string.

    Returns:
        str: Base64 data URI for the SVG.
    """
    svg_bytes = svg.encode("utf-8")
    b64 = base64.b64encode(svg_bytes).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"

# --- Webhook Signer ---

def sign_webhook_payload(
    payload: bytes,
    secret: str,
    algorithm: str = "sha256"
) -> str:
    """
    Sign a webhook payload using HMAC.

    Args:
        payload (bytes): The payload to sign.
        secret (str): The secret key.
        algorithm (str): Hash algorithm, e.g., 'sha256'.

    Returns:
        str: Hexadecimal signature string.
    """
    if algorithm.lower() not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    mac = hmac.new(secret.encode("utf-8"), payload, getattr(hashlib, algorithm))
    return mac.hexdigest()

def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str,
    algorithm: str = "sha256"
) -> bool:
    """
    Verify a webhook payload signature.

    Args:
        payload (bytes): The payload.
        signature (str): The signature to verify.
        secret (str): The secret key.
        algorithm (str): Hash algorithm.

    Returns:
        bool: True if valid, False otherwise.
    """
    expected_sig = sign_webhook_payload(payload, secret, algorithm)
    return hmac.compare_digest(expected_sig, signature)

# --- Example Usage & Tests ---

def _test_badge_svg() -> None:
    svg = generate_verification_badge_svg("alice", 42)
    assert "<svg" in svg and "alice" in svg and "Bounty #42" in svg
    b64 = badge_svg_to_base64(svg)
    assert b64.startswith("data:image/svg+xml;base64,")

def _test_webhook_signer() -> None:
    payload = b'{"event":"bounty_verified","user":"alice"}'
    secret = "supersecret"
    sig = sign_webhook_payload(payload, secret)
    assert isinstance(sig, str) and len(sig) == 64
    assert verify_webhook_signature(payload, sig, secret)
    assert not verify_webhook_signature(payload, "deadbeef"*8, secret)

if __name__ == "__main__":
    _test_badge_svg()
    _test_webhook_signer()