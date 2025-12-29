from __future__ import annotations

import os
import time
import json
import hmac
import hashlib
from typing import Any, Mapping, Protocol

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


# -----------------------
# Provider protocol
# -----------------------


class Provider(Protocol):
    name: str

    async def parse_event(self, raw_body: bytes, headers: Mapping[str, str], slack_client: Any | None = None) -> dict[str, Any] | None:
        """Return Slack-ready payload or None if event not relevant."""

    async def authorize(self, payload: str, *, actor: str, action: str) -> None:
        """Validate that the actor can perform the action. Raise HTTPForbidden on denial."""

    async def approve(self, payload: str, *, actor: str) -> None:
        """Approve a change given the encoded payload from Slack action."""

    async def request_changes(self, payload: str, *, actor: str, comment: str) -> None:
        """Request changes with a required comment."""

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


def set_actions(blocks: list[dict[str, Any]], *, state: str, provider: str, payload: str | None = None) -> list[dict[str, Any]]:
    """Toggle action buttons based on state: pending -> approve, approved -> merge, merged -> none."""
    if state == "pending":
        new_elements = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Approve ✅"},
                "style": "primary",
                "action_id": "change_request_approve",
                "value": encode_ref(provider, payload or ""),
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Request changes"},
                "style": "danger",
                "action_id": "request_changes",
                "value": encode_ref(provider, payload or ""),
            },
        ]
    elif state == "approved":
        new_elements = [{
            "type": "button",
            "text": {"type": "plain_text", "text": "Merge 🚀"},
            "style": "primary",
            "action_id": "pr_merge",
            "value": encode_ref(provider, payload or ""),
        }]
    else:  # merged or closed
        new_elements = []

    for idx, b in enumerate(blocks):
        if b.get("type") == "actions":
            if new_elements:
                b["elements"] = new_elements
                return blocks
            # remove actions block when no buttons are needed
            del blocks[idx]
            return blocks

    if new_elements:
        blocks.append({"type": "actions", "elements": new_elements})
    return blocks


def get_actor(body: Mapping[str, Any]) -> str:
    return body.get("user", {}).get("name") or body.get("user", {}).get("id", "unknown")


def require_provider(provider_key: str) -> Provider:
    provider = PROVIDERS.get(provider_key)
    if not provider:
        raise web.HTTPBadRequest(text="Unknown provider")
    return provider


async def ensure_authorized(provider: Provider, payload: str, actor: str, action: str, *, client, channel: str, user: str) -> bool:
    """Authorize or emit an ephemeral denial; returns True if authorized."""
    try:
        await provider.authorize(payload, actor=actor, action=action)
        return True
    except web.HTTPForbidden:
        verb = {
            "approve": "approve",
            "merge": "merge",
            "request_changes": "request changes",
        }.get(action, action)
        await client.chat_postEphemeral(
            channel=channel,
            user=user,
            text=f"You don't have permission to {verb} this change.",
        )
        return False


def is_pr_message(msg: Mapping[str, Any], *, number: int, repo_full: str) -> bool:
    """Heuristic to identify a PR message we posted earlier."""
    text = msg.get("text", "")
    if f"PR #{number}" in text or repo_full in text:
        return True

    for b in msg.get("blocks", []) or []:
        if b.get("type") == "header":
            header_text = b.get("text", {}).get("text", "")
            if header_text.startswith(f"PR #{number}"):
                return True
    return False


async def find_existing_message_ts(*, channel_id: str, slack_client: Any | None, match: Any, pages: int = 3, page_size: int = 200) -> str | None:
    """Search recent channel history for a message matching `match(msg)`.

    Bounded scan (pages*page_size) to avoid heavy history reads.
    """
    if not slack_client:
        return None

    cursor = None
    for _ in range(pages):
        resp = await slack_client.conversations_history(
            channel=channel_id, limit=page_size, cursor=cursor
        )
        for msg in resp.get("messages", []) or []:
            if match(msg):
                return msg.get("ts")

        cursor = resp.get("response_metadata", {}).get("next_cursor") or None
        if not cursor:
            break
    return None


# -----------------------
# Slack Bolt async app
# -----------------------
bolt_app = AsyncApp(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"],
)


class GithubProvider:
    name = "github"

    def _decode_payload(self, payload: str) -> tuple[str, str, int]:
        repo_full, installation_id, num = payload.split("|", 2)
        return repo_full, installation_id, int(num)

    async def _has_write_access(self, repo_full: str, username: str, installation_id: str) -> bool:
        """Check if the GitHub user has write/maintain/admin on the repo."""
        if not username:
            return False

        owner, repo = repo_full.split("/", 1)
        inst_token = await github_installation_token(installation_id)

        url = f"https://api.github.com/repos/{owner}/{repo}/collaborators/{username}/permission"
        headers = {
            "Authorization": f"Bearer {inst_token}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(url, headers=headers)
            if r.status_code == 404:
                return False
            r.raise_for_status()

        perm = r.json().get("permission")
        return perm in {"admin", "maintain", "write"}

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

    async def _request_changes(self, repo_full: str, number: int, *, actor: str, installation_id: str, comment: str) -> None:
        owner, name = repo_full.split("/", 1)
        inst_token = await github_installation_token(installation_id)

        url = f"https://api.github.com/repos/{owner}/{name}/pulls/{number}/reviews"
        headers = {"Authorization": f"Bearer {inst_token}",
                   "Accept": "application/vnd.github+json"}
        payload = {"event": "REQUEST_CHANGES",
                   "body": f"Changes requested via Slack by {actor}: {comment}"}

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()

    async def authorize(self, payload: str, *, actor: str, action: str) -> None:
        """Authorize based on GitHub repo permissions (write+)."""
        repo_full, installation_id, _ = self._decode_payload(payload)
        has_access = await self._has_write_access(repo_full, actor, installation_id)
        if not has_access:
            raise web.HTTPForbidden(text="Insufficient permissions")

    async def parse_event(self, raw_body: bytes, headers: Mapping[str, str], slack_client: Any | None = None) -> dict[str, Any] | None:
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

        description = (pr.get("body") or "").strip()
        if description:
            max_desc = 2800  # stay under Slack block limits
            if len(description) > max_desc:
                description = description[:max_desc] + "…"
        else:
            description = "_No description provided._"

        channel_id = os.environ["SLACK_PR_CHANNEL_ID"]
        files = await self._pr_files(repo_full, number, installation_id)
        diff_blocks = build_diff_blocks(files, max_files=6)

        action_payload = f"{repo_full}|{installation_id}|{number}"

        blocks = [
            {"type": "header", "text": {"type": "plain_text",
                                        "text": f"PR #{number}: {title}"}},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": f"*Repo:* `{repo_full}`\n*Author:* `{author}`\n<{url}|View on GitHub>"}},
            {"type": "section",
             "text": {"type": "mrkdwn", "text": f"*Description:*\n{description}"}},
            *diff_blocks,
            {"type": "context", "block_id": "state", "elements": [
                {"type": "mrkdwn", "text": "*State:* Pending approval"}
            ]},
        ]
        blocks = set_actions(blocks, state="pending",
                             provider=self.name, payload=action_payload)

        message: dict[str, Any] = {
            "channel": channel_id,
            "text": f"PR #{number}: {title}",
            "blocks": blocks,
        }

        if action == "synchronize":
            existing_ts = await find_existing_message_ts(
                channel_id=channel_id,
                slack_client=slack_client,
                match=lambda m: is_pr_message(
                    m, number=number, repo_full=repo_full),
            )
            if existing_ts:
                message["ts"] = existing_ts

        return message

    async def approve(self, payload: str, *, actor: str) -> None:
        repo_full, installation_id, num = self._decode_payload(payload)
        await self._approve_pr(repo_full, num, actor=actor, installation_id=installation_id)

    async def request_changes(self, payload: str, *, actor: str, comment: str) -> None:
        repo_full, installation_id, num = self._decode_payload(payload)
        await self._request_changes(repo_full, num, actor=actor, installation_id=installation_id, comment=comment)

    async def merge(self, payload: str, *, actor: str) -> None:
        repo_full, installation_id, num = self._decode_payload(payload)
        await self._merge_pr(repo_full, num, actor=actor, installation_id=installation_id)


PROVIDERS: dict[str, Provider] = {
    "github": GithubProvider(),
}


@bolt_app.action("change_request_approve")
async def on_change_request_approve(ack, body, client):
    await ack()
    provider_key, payload = decode_ref(body["actions"][0]["value"])
    actor = get_actor(body)
    provider = require_provider(provider_key)

    if not await ensure_authorized(provider, payload, actor, "approve", client=client, channel=body["channel"]["id"], user=body["user"]["id"]):
        return

    await provider.approve(payload, actor=actor)
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    blocks = body["message"].get("blocks", [])
    blocks = set_state(blocks, f"*State:* Approved by {actor} — pending merge")
    blocks = set_actions(blocks, state="approved",
                         provider=provider_key, payload=payload)
    await client.chat_update(channel=channel, ts=ts, blocks=blocks, text=body["message"].get("text", ""))

    await client.chat_postEphemeral(
        channel=channel,
        user=body["user"]["id"],
        text="✅ Change approved",
    )


@bolt_app.action("request_changes")
async def on_request_changes(ack, body, client):
    await ack()
    provider_key, payload = decode_ref(body["actions"][0]["value"])
    actor = get_actor(body)
    provider = require_provider(provider_key)

    if not await ensure_authorized(provider, payload, actor, "request_changes", client=client, channel=body["channel"]["id"], user=body["user"]["id"]):
        return

    await client.views_open(
        trigger_id=body["trigger_id"],
        view={
            "type": "modal",
            "callback_id": "request_changes_submit",
            "title": {"type": "plain_text", "text": "Request changes"},
            "submit": {"type": "plain_text", "text": "Send"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "private_metadata": json.dumps({
                "provider_key": provider_key,
                "payload": payload,
                "channel": body["channel"]["id"],
                "ts": body["message"]["ts"],
                "text": body["message"].get("text", ""),
                "blocks": body["message"].get("blocks", []),
            }),
            "blocks": [
                {
                    "type": "input",
                    "block_id": "comment",
                    "element": {
                        "type": "plain_text_input",
                        "multiline": True,
                        "action_id": "value",
                        "placeholder": {"type": "plain_text", "text": "Describe what needs to change"},
                    },
                    "label": {"type": "plain_text", "text": "Comment"},
                }
            ],
        },
    )


@bolt_app.view("request_changes_submit")
async def handle_request_changes_submit(ack, body, client, view):
    await ack()
    meta = json.loads(view.get("private_metadata", "{}"))
    provider_key = meta.get("provider_key")
    payload = meta.get("payload")
    channel = meta.get("channel")
    ts = meta.get("ts")
    original_text = meta.get("text", "")
    blocks = meta.get("blocks") or []

    if not (provider_key and payload and channel and ts):
        return

    provider = PROVIDERS.get(provider_key)
    if not provider:
        return

    actor = get_actor(body)
    comment = view["state"]["values"]["comment"]["value"].get(
        "value", "").strip()
    if not comment:
        comment = "(no comment provided)"

    if not await ensure_authorized(provider, payload, actor, "request_changes", client=client, channel=channel, user=body["user"]["id"]):
        return

    await provider.request_changes(payload, actor=actor, comment=comment)

    blocks = set_state(
        blocks, f"*State:* Changes requested by {actor}\n>{comment}")
    blocks = set_actions(blocks, state="changes_requested",
                         provider=provider_key, payload=payload)

    await client.chat_update(channel=channel, ts=ts,
                             blocks=blocks, text=original_text)

    await client.chat_postEphemeral(
        channel=channel,
        user=body["user"]["id"],
        text="Changes requested and comment posted.",
    )


@bolt_app.action("pr_merge")
async def on_pr_merge(ack, body, client):
    await ack()
    provider_key, payload = decode_ref(body["actions"][0]["value"])
    actor = get_actor(body)
    provider = require_provider(provider_key)

    if not await ensure_authorized(provider, payload, actor, "merge", client=client, channel=body["channel"]["id"], user=body["user"]["id"]):
        return

    await provider.merge(payload, actor=actor)

    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    blocks = body["message"].get("blocks", [])
    blocks = set_state(blocks, f"*State:* Merged by {actor}")
    blocks = set_actions(blocks, state="merged",
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
    message = await PROVIDERS["github"].parse_event(raw, request.headers, slack_client=bolt_app.client)

    if message:
        if "ts" in message:
            ts = message["ts"]
            payload = {k: v for k, v in message.items() if k != "ts"}
            await bolt_app.client.chat_update(ts=ts, **payload)
        else:
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
