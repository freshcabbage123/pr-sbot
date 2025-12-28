from __future__ import annotations

import os
import time
import json
import hmac
import hashlib
from typing import Any, Mapping, Protocol, runtime_checkable

import httpx
import jwt
from aiohttp import web
from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.aiohttp import to_bolt_request, to_aiohttp_response
from dotenv import load_dotenv
load_dotenv()


# -----------------------
# GitHub helpers
# -----------------------
def verify_github_signature(raw_body: bytes, signature_256: str | None, secret: str) -> None:
    if not signature_256 or not signature_256.startswith("sha256="):
        raise web.HTTPUnauthorized(
            text="Missing/invalid GitHub signature (X-Hub-Signature-256)")

    expected = "sha256=" + \
        hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_256):
        raise web.HTTPUnauthorized(text="Bad GitHub signature")


def github_app_jwt() -> str:
    app_id = os.environ["GITHUB_APP_ID"]
    private_key_pem = os.environ["GITHUB_PRIVATE_KEY_PEM"].replace("\\n", "\n")

    now = int(time.time())
    payload = {"iat": now - 30, "exp": now + 8 * 60, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


async def github_installation_token(installation_id: str) -> str:
    """Get an installation token for the given installation.

    This lets the bot work across multiple GitHub orgs/repos without
    hard-coding a single installation id.
    """
    token = github_app_jwt()

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json"}

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, headers=headers)
        r.raise_for_status()
        return r.json()["token"]


# -----------------------
# Slack-friendly block helpers
# -----------------------
def build_diff_blocks(files: list[dict[str, Any]], max_files: int = 6) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []

    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": f"*Changed files:* {len(files)}"}
    })

    for f in files[:max_files]:
        filename = f.get("filename", "(unknown)")
        status = f.get("status", "modified")
        patch = f.get("patch") or "(diff too large / not available)"

        patch = patch[:2400]

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*`{filename}`* ({status})\n```{patch}```"
            }
        })

    if len(files) > max_files:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_Showing first {max_files} files. View full diff on provider._"}]
        })

    return blocks


def build_plain_block(title: str, body: str) -> list[dict[str, Any]]:
    """Minimal block set for non-file change requests (e.g., DB/UI updates)."""
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": body}},
    ]

# -----------------------
# Provider protocol
# -----------------------


@runtime_checkable
class Provider(Protocol):
    name: str

    async def parse_event(self, raw_body: bytes, headers: Mapping[str, str]) -> dict[str, Any] | None:
        """Return Slack-ready payload or None if event not relevant."""

    async def approve(self, payload: str, *, actor: str) -> None:
        """Approve a change given the encoded payload from Slack action."""

    async def merge(self, payload: str, *, actor: str) -> None:
        """Merge a change given the encoded payload from Slack action."""


def encode_ref(provider: str, payload: str) -> str:
    return f"{provider}:{payload}"


def decode_ref(value: str) -> tuple[str, str]:
    provider, payload = value.split(":", 1)
    return provider, payload


def set_state(blocks: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
    # Update or append a state context block for Slack message updates
    for b in blocks:
        if b.get("block_id") == "state" and b.get("type") == "context":
            if b.get("elements"):
                b["elements"][0]["text"] = text
            return blocks

    blocks.append({
        "type": "context",
        "block_id": "state",
        "elements": [{"type": "mrkdwn", "text": text}],
    })
    return blocks


def set_actions(blocks: list[dict[str, Any]], *, approved: bool, provider: str, payload: str) -> list[dict[str, Any]]:
    """Toggle action buttons: show approve OR merge depending on state."""
    new_elements: list[dict[str, Any]]
    if approved:
        new_elements = [{
            "type": "button",
            "text": {"type": "plain_text", "text": "Merge 🚀"},
            "style": "primary",
            "action_id": "pr_merge",
            "value": encode_ref(provider, payload),
        }]
    else:
        new_elements = [{
            "type": "button",
            "text": {"type": "plain_text", "text": "Approve ✅"},
            "style": "primary",
            "action_id": "pr_approve",
            "value": encode_ref(provider, payload),
        }]

    for b in blocks:
        if b.get("type") == "actions":
            b["elements"] = new_elements
            return blocks

    blocks.append({"type": "actions", "elements": new_elements})
    return blocks


# -----------------------
# Slack Bolt async app
# -----------------------
bolt_app = AsyncApp(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"],
)


class GithubProvider:
    name = "gh"

    async def _pr_files(self, repo_full: str, number: int, installation_id: str) -> list[dict[str, Any]]:
        owner, repo = repo_full.split("/", 1)
        inst_token = await github_installation_token(installation_id)

        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}/files"
        headers = {
            "Authorization": f"Bearer {inst_token}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            return r.json()

    async def _approve_pr(self, repo_full: str, number: int, *, actor: str, installation_id: str) -> None:
        owner, name = repo_full.split("/", 1)
        inst_token = await github_installation_token(installation_id)

        url = f"https://api.github.com/repos/{owner}/{name}/pulls/{number}/reviews"
        headers = {"Authorization": f"Bearer {inst_token}",
                   "Accept": "application/vnd.github+json"}
        payload = {"event": "APPROVE",
                   "body": f"Approved via Slack by {actor}"}

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()

    async def _merge_pr(self, repo_full: str, number: int, *, actor: str, installation_id: str) -> None:
        owner, name = repo_full.split("/", 1)
        inst_token = await github_installation_token(installation_id)

        url = f"https://api.github.com/repos/{owner}/{name}/pulls/{number}/merge"
        headers = {"Authorization": f"Bearer {inst_token}",
                   "Accept": "application/vnd.github+json"}
        payload = {"merge_method": "squash",
                   "commit_title": f"Merge PR #{number} (via Slack by {actor})"}

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.put(url, headers=headers, json=payload)
            r.raise_for_status()

    async def parse_event(self, raw_body: bytes, headers: Mapping[str, str]) -> dict[str, Any] | None:
        verify_github_signature(
            raw_body=raw_body,
            signature_256=headers.get("X-Hub-Signature-256"),
            secret=os.environ["GITHUB_WEBHOOK_SECRET"],
        )

        event = headers.get("X-GitHub-Event", "")
        payload: dict[str, Any] = json.loads(raw_body.decode("utf-8"))

        if event != "pull_request":
            return None

        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize"}:
            return None

        pr = payload["pull_request"]
        repo_full = payload["repository"]["full_name"]
        installation_id = payload.get("installation", {}).get("id")
        if not installation_id:
            raise web.HTTPInternalServerError(
                text="Missing GitHub installation id")
        installation_id = str(installation_id)
        number = pr["number"]
        title = pr.get("title", "Pull request")
        url = pr.get("html_url")
        author = pr.get("user", {}).get("login", "unknown")

        channel_id = os.environ["SLACK_PR_CHANNEL_ID"]
        files = await self._pr_files(repo_full, number, installation_id)
        diff_blocks = build_diff_blocks(files, max_files=6)

        action_payload = f"{repo_full}|{installation_id}|{number}"

        return {
            "channel": channel_id,
            "text": f"PR #{number}: {title}",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text",
                                            "text": f"PR #{number}: {title}"}},
                {"type": "section",
                 "text": {"type": "mrkdwn", "text": f"*Repo:* `{repo_full}`\n*Author:* `{author}`\n<{url}|View on GitHub>"}},
                *diff_blocks,
                {"type": "context", "block_id": "state", "elements": [
                    {"type": "mrkdwn", "text": "*State:* Pending approval"}
                ]},
                {"type": "actions", "elements": [
                    {"type": "button",
                     "text": {"type": "plain_text", "text": "Approve ✅"},
                     "style": "primary",
                     "action_id": "pr_approve",
                     "value": encode_ref(self.name, action_payload)},
                ]},
            ],
        }

    async def approve(self, payload: str, *, actor: str) -> None:
        repo_full, installation_id, num = payload.split("|", 2)
        await self._approve_pr(repo_full, int(num), actor=actor, installation_id=installation_id)

    async def merge(self, payload: str, *, actor: str) -> None:
        repo_full, installation_id, num = payload.split("|", 2)
        await self._merge_pr(repo_full, int(num), actor=actor, installation_id=installation_id)


PROVIDERS: dict[str, Provider] = {
    "gh": GithubProvider(),
}


@bolt_app.action("pr_approve")
async def on_pr_approve(ack, body, client):
    await ack()
    provider_key, payload = decode_ref(body["actions"][0]["value"])
    actor = body["user"].get("name") or body["user"]["id"]

    provider = PROVIDERS.get(provider_key)
    if not provider:
        raise web.HTTPBadRequest(text="Unknown provider")

    await provider.approve(payload, actor=actor)
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    blocks = body["message"].get("blocks", [])
    blocks = set_state(blocks, f"*State:* Approved by {actor} — pending merge")
    blocks = set_actions(blocks, approved=True,
                         provider=provider_key, payload=payload)
    await client.chat_update(channel=channel, ts=ts, blocks=blocks, text=body["message"].get("text", ""))

    await client.chat_postEphemeral(
        channel=channel,
        user=body["user"]["id"],
        text="✅ Change approved",
    )


@bolt_app.action("pr_merge")
async def on_pr_merge(ack, body, client):
    await ack()
    provider_key, payload = decode_ref(body["actions"][0]["value"])
    actor = body["user"].get("name") or body["user"]["id"]

    provider = PROVIDERS.get(provider_key)
    if not provider:
        raise web.HTTPBadRequest(text="Unknown provider")

    await provider.merge(payload, actor=actor)

    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    blocks = body["message"].get("blocks", [])
    blocks = set_state(blocks, f"*State:* Merged by {actor}")
    blocks = set_actions(blocks, approved=True,
                         provider=provider_key, payload=payload)
    await client.chat_update(channel=channel, ts=ts, blocks=blocks, text=body["message"].get("text", ""))

    await client.chat_postEphemeral(
        channel=channel,
        user=body["user"]["id"],
        text="🚀 Change merged",
    )


# -----------------------
# aiohttp routes (Slack + providers on same server)
# -----------------------
async def slack_events(request: web.Request) -> web.Response:
    bolt_req = await to_bolt_request(request)
    bolt_resp = await bolt_app.async_dispatch(bolt_req)
    return await to_aiohttp_response(bolt_resp)


async def github_webhook(request: web.Request) -> web.Response:
    raw = await request.read()
    message = await PROVIDERS["gh"].parse_event(raw, request.headers)

    if message:
        await bolt_app.client.chat_postMessage(**message)

    return web.json_response({"ok": True})


def build_aiohttp_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/slack/events", slack_events)
    app.router.add_post("/webhook/github", github_webhook)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "3000"))
    web.run_app(build_aiohttp_app(), port=port)
