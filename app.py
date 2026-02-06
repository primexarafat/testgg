#!/usr/bin/env python3
"""
tg_token_bot_final.py

Final single-folder, no-path Telegram bot.

Rules enforced:
 - No folders allowed. /setacc accepts only a filename (no '/' or '\' or '..').
 - All files (bot script, FreeFire_pb2.py, account JSONs, outputs) must live in the same folder.
 - Single live status message. No UIDs printed. /ins runs all accounts in configured filename.
 - Replace BOT_TOKEN below with your bot token (no env).
"""

import os
import json
import asyncio
import base64
import logging
from typing import List, Tuple, Dict, Any, Optional

from telegram import Update, Document
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters,
    ConversationHandler
)
import httpx
from Crypto.Cipher import AES
from google.protobuf import json_format

# ---------------- CONFIG ----------------
BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"   # <-- set your bot token here (no env)
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB52"

DEFAULT_WORKERS = 5
MAX_RETRY = 3
HTTP_TIMEOUT = 30.0
# ----------------------------------------

# Must have FreeFire_pb2.py in same folder
try:
    import FreeFire_pb2  # placed beside this script
except Exception as e:
    raise RuntimeError("Missing FreeFire_pb2.py in same folder. Place FreeFire_pb2.py next to the script.") from e

# Conversation states
WAIT_FILE, WAIT_COUNT, WAIT_WORKERS = range(3)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------- crypto / proto helpers ----------------
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len]) * pad_len

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(plaintext))

def json_to_proto_bytes(json_obj: Dict[str, Any], proto_cls) -> bytes:
    m = proto_cls()
    json_format.ParseDict(json_obj, m)
    return m.SerializeToString()


# ---------------- network / API calls ----------------
async def get_access_token_from_ffm(account_query: str, client: httpx.AsyncClient) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"{account_query}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    r = await client.post(url, data=payload, headers=headers, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    js = r.json()
    return js.get("access_token", "0"), js.get("open_id", "0")

async def create_jwt_for_account(uid: str, password: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    account_q = f"uid={uid}&password={password}"
    access_token, open_id = await get_access_token_from_ffm(account_q, client)
    if not access_token or access_token == "0":
        raise RuntimeError("Failed to get access token")
    body = {
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    }
    proto_bytes = json_to_proto_bytes(body, FreeFire_pb2.LoginReq)
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2022.3.47f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    r = await client.post(url, data=payload, headers=headers, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    login_res_msg = FreeFire_pb2.LoginRes()
    login_res_msg.ParseFromString(r.content)
    msg_dict = json_format.MessageToDict(login_res_msg, preserving_proto_field_name=True)
    token = msg_dict.get("token")
    if not token:
        raise RuntimeError("No token in MajorLogin response")
    return {"token": token, "meta": msg_dict}


# ---------------- account helpers (same folder only) ----------------
def load_accounts_from_bytes(data_bytes: bytes) -> List[Tuple[str, str]]:
    """Parse JSON bytes and return list of (uid, password)."""
    data = json.loads(data_bytes.decode("utf-8"))
    if not isinstance(data, list):
        raise ValueError("JSON must be a list of account objects")
    accounts: List[Tuple[str, str]] = []
    for entry in data:
        uid = None
        password = None
        if isinstance(entry, dict):
            uid = entry.get("uid") or entry.get("id") or entry.get("account") or entry.get("userid")
            password = entry.get("password") or entry.get("pw") or entry.get("pass")
        else:
            s = str(entry)
            if ":" in s:
                uid, password = s.split(":", 1)
        if uid is None or password is None:
            continue
        accounts.append((str(uid), str(password)))
    return accounts

def validate_local_filename(filename: str) -> str:
    """
    Enforce filename-only (no path characters, no ..). Return absolute path in cwd.
    """
    if not filename or any(sep in filename for sep in ("/", "\\") ) or ".." in filename:
        raise ValueError("Filename must be a simple filename with no path (no '/' or '\\' or '..').")
    abs_path = os.path.abspath(os.path.join(os.getcwd(), filename))
    if os.path.dirname(abs_path) != os.getcwd():
        raise ValueError("File must be in the same folder as the bot script.")
    return abs_path

def load_accounts_from_local_file(filename: str) -> List[Tuple[str, str]]:
    path = validate_local_filename(filename)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        data = f.read()
    return load_accounts_from_bytes(data)

def save_tokens_to_file(tokens: List[Dict[str, Any]], input_basename: str) -> str:
    base = os.path.basename(input_basename)
    name, _ = os.path.splitext(base)
    out_name = f"{name}_tokens.json"
    out_path = os.path.abspath(os.path.join(os.getcwd(), out_name))
    with open(out_path, "w", encoding="utf-8") as f:
        out_list = []
        for t in tokens:
            if t.get("token"):
                out_list.append({"token": t["token"]})
            else:
                out_list.append({"token": None, "uid": t.get("uid"), "error": t.get("error")})
        json.dump(out_list, f, indent=2)
    return out_path


# ---------------- UI: single-edit live status (no UIDs) ----------------
async def edit_status(context: ContextTypes.DEFAULT_TYPE, chat_id: int, msg_id: int,
                      processed: int, total: int, success: int, failed: int, recent: List[str], running: bool, workers: int):
    pct = int((processed / total) * 100) if total > 0 else 100
    recent_str = " ".join(recent[-12:]) if recent else ""
    state = "⏳ Running..." if running else "✅ Finished"
    text = (
        f"<b>🎯 Token generation</b>\n"
        f"<b>Status:</b> {state}\n"
        f"<b>Workers:</b> {workers}\n\n"
        f"<b>Progress:</b> {processed}/{total} ({pct}%)\n"
        f"✅ Success: <b>{success}</b>    ❌ Failed: <b>{failed}</b>\n"
        f"<b>Recent:</b> {recent_str}\n\n"
        f"_The result file will be sent when finished._"
    )
    try:
        await context.bot.edit_message_text(text, chat_id=chat_id, message_id=msg_id, parse_mode=ParseMode.HTML)
    except Exception:
        logger.debug("edit_status: ignored edit error")


# ---------------- worker (counts only) ----------------
async def worker_task(worker_id: int, queue: asyncio.Queue, results: List[Dict[str, Any]],
                      sem: asyncio.Semaphore, counters: Dict[str, int], recent: List[str],
                      context: ContextTypes.DEFAULT_TYPE, chat_id: int, status_msg_id: int, total: int, workers: int):
    async with httpx.AsyncClient() as client:
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break
            uid, pwd = item
            attempt = 0
            ok = False
            while attempt < MAX_RETRY and not ok:
                attempt += 1
                try:
                    async with sem:
                        out = await create_jwt_for_account(uid, pwd, client)
                    results.append({"uid": uid, "token": out["token"]})
                    counters["processed"] += 1
                    counters["success"] += 1
                    recent.append("✅")
                    await edit_status(context, chat_id, status_msg_id, counters["processed"], total, counters["success"], counters["failed"], recent, True, workers)
                    ok = True
                except Exception as e:
                    logger.debug(f"worker {worker_id} attempt {attempt} failed (uid hidden): {e}")
                    if attempt >= MAX_RETRY:
                        results.append({"uid": uid, "token": None, "error": str(e)})
                        counters["processed"] += 1
                        counters["failed"] += 1
                        recent.append("❌")
                        await edit_status(context, chat_id, status_msg_id, counters["processed"], total, counters["success"], counters["failed"], recent, True, workers)
                    else:
                        await asyncio.sleep(1 + (2 ** attempt))
            queue.task_done()


# ---------------- orchestrator ----------------
async def run_generation_from_accounts(context: ContextTypes.DEFAULT_TYPE, chat_id: int, accounts: List[Tuple[str,str]], workers: int, file_basename: str):
    total = len(accounts)
    if total == 0:
        await context.bot.send_message(chat_id=chat_id, text="No accounts to process.")
        return

    q: asyncio.Queue = asyncio.Queue()
    for a in accounts:
        await q.put(a)
    for _ in range(workers):
        await q.put(None)

    results: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(workers if workers > 0 else 1)
    counters = {"processed": 0, "success": 0, "failed": 0}
    recent: List[str] = []

    # initial single status message
    msg = await context.bot.send_message(chat_id=chat_id,
                                         text=f"<b>🎯 Token generation</b>\nStarting... (0/{total})\nWorkers: {workers}",
                                         parse_mode=ParseMode.HTML)
    status_msg_id = msg.message_id

    tasks = [asyncio.create_task(worker_task(i+1, q, results, sem, counters, recent, context, chat_id, status_msg_id, total, workers))
             for i in range(workers)]
    await q.join()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    # final edit
    await edit_status(context, chat_id, status_msg_id, counters["processed"], total, counters["success"], counters["failed"], recent, False, workers)

    # save tokens and send file
    out_path = save_tokens_to_file(results, file_basename)
    try:
        await context.bot.send_document(chat_id=chat_id, document=open(out_path, "rb"))
    except Exception as e:
        await context.bot.send_message(chat_id=chat_id, text=f"Could not upload result file: {e}")


# ---------------- Telegram handlers ----------------
async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send your accounts JSON file as a document (list of objects with 'uid' and 'password'),\n"
        "or configure a local filename with /setacc filename.json (file must be in same folder as this bot script).\n\n"
        "Commands:\n"
        "/setacc <filename>  — set local accounts file (filename only, no path)\n"
        "/acc                — check configured file exists and show how many accounts\n"
        "/ins [workers]      — create tokens for all accounts in configured file and return tokens file\n\n"
        "Or upload a JSON file now and follow prompts."
    )
    return WAIT_FILE

# Upload flow
async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc: Document = update.message.document
    if not doc or not doc.file_name.lower().endswith(".json"):
        await update.message.reply_text("Please upload a .json file as a document (accounts list).")
        return WAIT_FILE

    file_obj = await doc.get_file()
    bytes_content = await file_obj.download_as_bytearray()
    try:
        accounts = load_accounts_from_bytes(bytes(bytes_content))
    except Exception as e:
        await update.message.reply_text(f"Failed to parse JSON: {e}")
        return WAIT_FILE

    if not accounts:
        await update.message.reply_text("No valid accounts found in the JSON file (need uid and password).")
        return WAIT_FILE

    context.user_data["accounts"] = accounts
    context.user_data["file_basename"] = doc.file_name
    total = len(accounts)
    await update.message.reply_text(f"Loaded {total} account(s). How many tokens do you want to make? (send a number, or 0 for all)")
    return WAIT_COUNT

async def count_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    try:
        n = int(text)
    except Exception:
        await update.message.reply_text("Send a valid integer.")
        return WAIT_COUNT
    total = len(context.user_data.get("accounts", []))
    if n <= 0:
        n = total
    n = min(n, total)
    context.user_data["selected_count"] = n
    suggested = min(DEFAULT_WORKERS, n) if n > 0 else DEFAULT_WORKERS
    await update.message.reply_text(f"Will process {n} accounts. How many workers to use? (recommended {suggested})")
    return WAIT_WORKERS

async def workers_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    try:
        w = int(text)
        if w <= 0: raise ValueError()
    except Exception:
        await update.message.reply_text("Send a positive integer for workers.")
        return WAIT_WORKERS

    context.user_data["workers"] = w
    if context.user_data.get("generating"):
        await update.message.reply_text("A run is already in progress for you. Wait until it finishes.")
        return ConversationHandler.END

    context.user_data["generating"] = True
    await update.message.reply_text(f"Starting generation for {context.user_data['selected_count']} accounts with {w} worker(s). Live status will be updated in one message.")
    accounts = context.user_data.get("accounts", [])[:context.user_data["selected_count"]]
    file_basename = context.user_data.get("file_basename", "uploaded.json")
    asyncio.create_task(run_generation_from_accounts(context, update.effective_chat.id, accounts, w, file_basename))
    return ConversationHandler.END

async def cancel_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("Cancelled.")
    return ConversationHandler.END

# /setacc filename.json  -> only filename allowed (no path)
async def setacc_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        await update.message.reply_text("Usage: /setacc filename.json  (filename only, no path).")
        return
    filename = parts[1].strip()
    # reject any path-like input
    if any(sep in filename for sep in ("/", "\\") ) or ".." in filename:
        await update.message.reply_text("Filename must not include path characters or '..'. Provide a simple filename located beside the bot.")
        return
    abs_path = os.path.abspath(os.path.join(os.getcwd(), filename))
    if os.path.dirname(abs_path) != os.getcwd():
        await update.message.reply_text("File must be in the same folder as the bot script.")
        return
    if not os.path.exists(abs_path):
        await update.message.reply_text("File not found in this folder.")
        return
    context.user_data["acc_path"] = filename
    await update.message.reply_text(f"Configured account file: {filename}")

# /acc -> check configured filename and show count
async def acc_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    fname = context.user_data.get("acc_path")
    if not fname:
        await update.message.reply_text("No account file configured. Use /setacc filename.json to set one, or upload a file.")
        return
    try:
        accounts = load_accounts_from_local_file(fname)
    except FileNotFoundError:
        await update.message.reply_text("Configured file not found.")
        return
    except Exception as e:
        await update.message.reply_text(f"Could not read configured file: {e}")
        return
    await update.message.reply_text(f"Configured file connected. Contains {len(accounts)} account(s).")

# /ins [workers] -> process all accounts from configured local filename
async def ins_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    parts = text.split()
    workers_arg = None
    if len(parts) >= 2:
        try:
            workers_arg = int(parts[1])
            if workers_arg <= 0:
                raise ValueError()
        except Exception:
            await update.message.reply_text("Invalid workers argument. Usage: /ins [workers]")
            return

    fname = context.user_data.get("acc_path")
    if not fname:
        await update.message.reply_text("No account file configured. Use /setacc filename.json to set one first.")
        return
    try:
        accounts = load_accounts_from_local_file(fname)
    except FileNotFoundError:
        await update.message.reply_text("Configured account file not found.")
        return
    except Exception as e:
        await update.message.reply_text(f"Could not read configured file: {e}")
        return

    total = len(accounts)
    if total == 0:
        await update.message.reply_text("Configured account file contains no valid accounts.")
        return

    workers = workers_arg if workers_arg is not None else min(DEFAULT_WORKERS, total)
    if context.user_data.get("generating"):
        await update.message.reply_text("A job is already running for you. Wait until it finishes.")
        return
    context.user_data["generating"] = True
    await update.message.reply_text(f"Starting generation for {total} accounts with {workers} worker(s). Live status will be updated in one message.")
    asyncio.create_task(run_generation_from_accounts(context, update.effective_chat.id, accounts, workers, fname))


# ---------------- bootstrap ----------------
def main():
    if BOT_TOKEN == "" or BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        raise RuntimeError("Edit this file and set BOT_TOKEN variable to your Telegram bot token.")

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    # Upload conversation
    conv = ConversationHandler(
        entry_points=[CommandHandler("start", start_handler)],
        states={
            WAIT_FILE: [MessageHandler(filters.Document.ALL & (~filters.COMMAND), document_handler)],
            WAIT_COUNT: [MessageHandler(filters.TEXT & (~filters.COMMAND), count_handler)],
            WAIT_WORKERS: [MessageHandler(filters.TEXT & (~filters.COMMAND), workers_handler)],
        },
        fallbacks=[CommandHandler("cancel", cancel_handler)],
        allow_reentry=True,
    )
    app.add_handler(conv)

    # Commands
    app.add_handler(CommandHandler("setacc", setacc_handler))
    app.add_handler(CommandHandler("acc", acc_handler))
    app.add_handler(CommandHandler("ins", ins_handler))

    # Accept documents
    app.add_handler(MessageHandler(filters.Document.ALL, document_handler))

    logger.info("Bot starting (final, single-folder, no-path)...")
    app.run_polling()

if __name__ == "__main__":
    main()
