"""Pydantic contracts for Gmail connection and mailbox endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class GmailAuthResponse(BaseModel):
    mode: str
    authorization_url: str
    message: str


class GmailCallbackResponse(BaseModel):
    connected: bool
    mode: str
    message: str


class GmailEmailSummary(BaseModel):
    id: str
    from_: str = Field(alias="from")
    subject: str
    date: str
    snippet: str = ""


class GmailEmailListResponse(BaseModel):
    mode: str
    emails: list[GmailEmailSummary]