from __future__ import annotations

import os
import time
import json
import hmac
import hashlib
from typing import Any

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


async def github_installation_token() -> str:
    installation_id = os.environ["GITHUB_INSTALLATION_ID"]
    token = github_app_jwt()

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {"Authorization": f"Bearer {token}",
               "Accept": "application/vnd.github+json"}

    async with httpx.AsyncClient(timeout=11) as client:
        r = await client.post(url, headers=headers)
        r.raise_for_status()
        return r.json()["token"]


async def github_approve_pr(repo_full: str, number: int, *, actor: str) -> None:
    owner, name = repo_full.split("/", 1)
    inst_token = await github_installation_token()

    url = f"https://api.github.com/repos/{owner}/{name}/pulls/{number}/reviews"
    headers = {"Authorization": f"Bearer {inst_token}",
               "Accept": "application/vnd.github+json"}
    payload = {"event": "APPROVE", "body": f"Approved via Slack by {actor}"}

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(url, headers=headers, json=payload)
        r.raise_for_status()

async def github_pr_files(repo_full: str, number: int) -> list[dict[str, Any]]:
    owner, repo = repo_full.split("/", 1)
    inst_token = await github_installation_token()

    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{number}/files"
    headers = {
        "Authorization": f"Bearer {inst_token}",
        "Accept": "application/vnd.github+json",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        return r.json()
    
def build_diff_blocks(files: list[dict[str, Any]], max_files: int = 6) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []

    # small header line
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": f"*Changed files:* {len(files)}"}
    })

    for f in files[:max_files]:
        filename = f.get("filename", "(unknown)")
        status = f.get("status", "modified")
        patch = f.get("patch") or "(diff too large / not available)"

        # keep the whole section under 3000 chars (Slack limit)
        # leave room for filename/status + markdown overhead
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
            "elements": [{"type": "mrkdwn", "text": f"_Showing first {max_files} files. View full diff on GitHub._"}]
        })

    return blocks

# -----------------------
# Slack Bolt async app
# -----------------------
bolt_app = AsyncApp(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"],
)


def encode_ref(repo_full: str, pr_number: int) -> str:
    return f"{repo_full}#{pr_number}"


def decode_ref(value: str) -> tuple[str, int]:
    repo, num = value.split("#", 1)
    return repo, int(num)


@bolt_app.action("pr_approve")
async def on_pr_approve(ack, body, client):
    await ack()
    repo_full, pr_number = decode_ref(body["actions"][0]["value"])
    actor = body["user"].get("name") or body["user"]["id"]
    await github_approve_pr(repo_full, pr_number, actor=actor)

    await client.chat_postEphemeral(
        channel=body["channel"]["id"],
        user=body["user"]["id"],
        text=f"✅ Approved {repo_full}#{pr_number}",
    )


# -----------------------
# aiohttp routes (Slack + GitHub on same server)
# -----------------------
async def slack_events(request: web.Request) -> web.Response:
    bolt_req = await to_bolt_request(request)
    bolt_resp = await bolt_app.async_dispatch(bolt_req)
    return await to_aiohttp_response(bolt_resp)


async def github_webhook(request: web.Request) -> web.Response:
    raw = await request.read()

    verify_github_signature(
        raw_body=raw,
        signature_256=request.headers.get("X-Hub-Signature-256"),
        secret=os.environ["GITHUB_WEBHOOK_SECRET"],
    )

    event = request.headers.get("X-GitHub-Event", "")
    payload: dict[str, Any] = json.loads(raw.decode("utf-8"))

    if event == "pull_request":
        action = payload.get("action")
        if action in {"opened", "reopened", "synchronize"}:
            pr = payload["pull_request"]
            repo_full = payload["repository"]["full_name"]
            number = pr["number"]
            title = pr["title"]
            url = pr["html_url"]
            author = pr["user"]["login"]

            channel_id = os.environ["SLACK_PR_CHANNEL_ID"]
            # await bolt_app.client.chat_postMessage(
            #     channel=channel_id,
            #     text=f"PR #{number}: {title}",
            #     blocks=[
            #         {"type": "header", "text": {"type": "plain_text",
            #                                     "text": f"PR #{number}: {title}"}},
            #         {"type": "section",
            #          "text": {"type": "mrkdwn", "text": f"*Repo:* `{repo_full}`\n*Author:* `{author}`\n<{url}|View on GitHub>"}},
            #         {"type": "actions", "elements": [
            #             {"type": "button",
            #              "text": {"type": "plain_text", "text": "Approve ✅"},
            #              "style": "primary",
            #              "action_id": "pr_approve",
            #              "value": encode_ref(repo_full, number)},
            #         ]},
            #     ],
            # )
            files = await github_pr_files(repo_full, number)
            diff_blocks = build_diff_blocks(files, max_files=6)
            await bolt_app.client.chat_postMessage(
                channel=channel_id,
                text=f"PR #{number}: {title}",
                blocks=[
                    {"type": "header", "text": {"type": "plain_text", "text": f"PR #{number}: {title}"}},
                    {"type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Repo:* `{repo_full}`\n*Author:* `{author}`\n<{url}|View on GitHub>"}},
                    *diff_blocks,
                    {"type": "actions", "elements": [
                        {"type": "button",
                        "text": {"type": "plain_text", "text": "Approve ✅"},
                        "style": "primary",
                        "action_id": "pr_approve",
                        "value": encode_ref(repo_full, number)},
                    ]},
                ],
            )

    return web.json_response({"ok": True})


def build_aiohttp_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/slack/events", slack_events)
    app.router.add_post("/webhook/github", github_webhook)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "3000"))
    web.run_app(build_aiohttp_app(), port=port)


# async def create_pr(
#     repo_full: str = "freshcabbage123/pr-sbot",
#     base: str = "main",
#     head: str = "feat123",
#     title: str = "chore: test PR (created by GitHub App)",
#     body: str = "Auto-created PR for Slack approval testing.",
# ) -> dict:
#     owner, repo = repo_full.split("/", 1)
#     inst = await github_installation_token()

#     url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
#     headers = {
#         "Authorization": f"Bearer {inst}",
#         "Accept": "application/vnd.github+json",
#         # "X-GitHub-Api-Version": "2022-11-28",
#     }
#     payload = {"title": title, "head": head, "base": base, "body": body}

#     async with httpx.AsyncClient(timeout=15) as client:
#         r = await client.post(url, headers=headers, json=payload)
#         if r.status_code == 422:
#             print("422 body:", r.text)
#         r.raise_for_status()
#         return r.json()
