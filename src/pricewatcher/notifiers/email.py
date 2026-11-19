"""SMTP email fallback client."""

from __future__ import annotations

import asyncio
import base64
from email.message import EmailMessage
import smtplib

from pricewatcher.config import EmailConfig
from pricewatcher.notifiers.waha import ChannelSendResult


def _redact_smtp_secrets(text: str, user: str, password: str) -> str:
    candidates: list[str] = []
    if password:
        candidates.append(password)
        candidates.append(base64.b64encode(password.encode()).decode("ascii"))
    if user and password:
        plain_token = f"\x00{user}\x00{password}".encode()
        candidates.append(base64.b64encode(plain_token).decode("ascii"))
    if user and len(user) >= 3:
        candidates.append(user)
        candidates.append(base64.b64encode(user.encode()).decode("ascii"))

    redacted = text
    for secret in sorted(set(candidates), key=len, reverse=True):
        if secret:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


class EmailClient:
    """Async wrapper around smtplib for SMTP/STARTTLS alerts."""

    def __init__(self, config: EmailConfig) -> None:
        self.config = config

    def _send_sync(self, to_addr: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.config.from_addr
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)

        user, password = self.config.effective_credentials()
        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=15) as smtp:
            smtp.ehlo()
            if self.config.use_tls:
                smtp.starttls()
                smtp.ehlo()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)

    async def send_email(self, to_addr: str, subject: str, body: str) -> ChannelSendResult:
        if not self.config.enabled:
            return ChannelSendResult(ok=False, error="Email notifications disabled")
        if not to_addr:
            return ChannelSendResult(ok=False, error="Recipient email not configured")

        try:
            await asyncio.to_thread(self._send_sync, to_addr, subject, body)
        except Exception as exc:
            user, password = self.config.effective_credentials()
            safe_detail = _redact_smtp_secrets(str(exc), user, password)
            return ChannelSendResult(ok=False, error=f"{type(exc).__name__}: {safe_detail}")
        return ChannelSendResult(ok=True)
