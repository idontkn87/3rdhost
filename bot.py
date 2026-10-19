# CREDIT - DK
# MAIN CHANNEL - DK HOSTING
# Hardened host: user code never inherits the host environment.

import os
import sys
import time
import json
import shutil
import zipfile
import subprocess
import threading
import html
import logging
import logging.handlers
import re
import signal
import hashlib
import resource
from collections import deque
from datetime import datetime

import psutil
from flask import Flask

import telebot
from telebot.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ReplyKeyboardMarkup,
    KeyboardButton,
)

# ============================================================
# SECRETS — environment only, no defaults
# ============================================================

def _require_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        print(f"ERROR: {name} is not set. Export it and start again. No default is built in.")
        sys.exit(1)
    return value


BOT_TOKEN = _require_env("BOT_TOKEN")
_owner_raw = _require_env("OWNER_ID")
if not _owner_raw.isdigit() or int(_owner_raw) <= 0:
    print("ERROR: OWNER_ID must be a positive Telegram user id.")
    sys.exit(1)
OWNER_ID = int(_owner_raw)


def redact(value):
    text = "" if value is None else str(value)
    if BOT_TOKEN:
        text = text.replace(BOT_TOKEN, "[redacted]")
    return text


class _RedactFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact(record.msg)
        if record.args:
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        record.exc_info = None
        record.exc_text = None
        return True


# ============================================================
# PATHS — host data is NOT inside the uploads tree
# ============================================================

STORAGE_DIR = "user_files"
UPLOAD_DIR = os.path.join(STORAGE_DIR, "uploads")
DATA_DIR = os.path.join(STORAGE_DIR, "data")
DATA_FILE = os.path.join(DATA_DIR, "users.json")
LOG_DIR = os.path.join(STORAGE_DIR, "logs")
HOST_LOG = os.path.join(LOG_DIR, "host.log")

for _d in (STORAGE_DIR, UPLOAD_DIR, DATA_DIR, LOG_DIR):
    os.makedirs(_d, exist_ok=True)

# Keep host metadata unreadable to a dropped-privilege sandbox user.
try:
    os.chmod(DATA_DIR, 0o700)
    os.chmod(LOG_DIR, 0o700)
except OSError:
    pass


def _migrate_legacy_paths():
    legacy_upload = os.path.join(STORAGE_DIR, "uplo556ads")
    if os.path.isdir(legacy_upload):
        if not os.path.isdir(UPLOAD_DIR) or not os.listdir(UPLOAD_DIR):
            if os.path.isdir(UPLOAD_DIR):
                os.rmdir(UPLOAD_DIR)
            os.replace(legacy_upload, UPLOAD_DIR)
        else:
            for name in os.listdir(legacy_upload):
                src = os.path.join(legacy_upload, name)
                dst = os.path.join(UPLOAD_DIR, name)
                if not os.path.exists(dst):
                    shutil.move(src, dst)
    legacy_data = os.path.join(STORAGE_DIR, "users.json")
    if os.path.isfile(legacy_data) and not os.path.isfile(DATA_FILE):
        os.replace(legacy_data, DATA_FILE)


_migrate_legacy_paths()

if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w", encoding="utf-8") as _f:
        json.dump({}, _f)
try:
    os.chmod(DATA_FILE, 0o600)
except OSError:
    pass

_log = logging.getLogger("dkhost")
_log.setLevel(logging.INFO)
_log.addFilter(_RedactFilter())
_handler = logging.handlers.RotatingFileHandler(
    HOST_LOG, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_handler.addFilter(_RedactFilter())
_log.addHandler(_handler)
_stream = logging.StreamHandler()
_stream.addFilter(_RedactFilter())
_stream.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
_log.addHandler(_stream)


def log_error(where, exc):
    _log.error("%s: %s", where, redact(exc))


# ============================================================
# LIMITS
# ============================================================

def _env_int(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


LIMIT_MEMORY_MB = _env_int("SANDBOX_MEMORY_MB", 256)
LIMIT_CPUS = _env_float("SANDBOX_CPUS", 0.5)
LIMIT_PIDS = _env_int("SANDBOX_PIDS", 100)
LIMIT_NOFILE = _env_int("SANDBOX_NOFILE", 64)
LIMIT_FSIZE_MB = _env_int("SANDBOX_FSIZE_MB", 20)
LIMIT_RUNTIME_SEC = _env_int("SANDBOX_RUNTIME_SEC", 300)
LIMIT_CPU_SEC = _env_int("SANDBOX_CPU_SEC", 120)
LIMIT_AS_MB = _env_int("SANDBOX_AS_MB", 256)
DEFAULT_CONCURRENT = _env_int("MAX_CONCURRENT", 2)
DEFAULT_DISK_MB = _env_int("DISK_QUOTA_MB", 100)
DEFAULT_UPLOAD_MB = _env_int("MAX_UPLOAD_MB", 20)
DEFAULT_FILE_LIMIT = _env_int("FILE_LIMIT", 2)
ZIP_MAX_FILES = _env_int("ZIP_MAX_FILES", 200)
ZIP_MAX_RATIO = _env_int("ZIP_MAX_RATIO", 100)
PIP_TIMEOUT = _env_int("PIP_TIMEOUT", 300)
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "none").strip() or "none"
DOCKER_IMAGE = os.environ.get("SANDBOX_IMAGE", "python:3.11-slim").strip() or "python:3.11-slim"
SANDBOX_UID = _env_int("SANDBOX_UID", 0)
SANDBOX_GID = _env_int("SANDBOX_GID", 0)
MAX_RESTARTS = 5

REQ_LINE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?"
    r"(==|>=|<=|~=|!=)[A-Za-z0-9.*!+_=-]+$"
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# ============================================================
# FLASK KEEP-ALIVE
# ============================================================

app = Flask(__name__)


@app.route("/")
def home():
    return "DK HOSTING BOT IS LIVE AND RUNNING!", 200


@app.route("/health")
def health():
    return {"status": "ok", "service": "DK HOSTING", "credit": "DK"}, 200


def run_web_server():
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


# ============================================================
# GLOBALS
# ============================================================

users = {}
active_scripts = {}   # (uid, fname) -> record
logs_store = {}       # (uid, fname) -> deque
log_meta = {}         # (uid, fname) -> {exit, note}
admin_states = {}
data_lock = threading.Lock()
state_lock = threading.Lock()
ISOLATION_MODE = "rlimit"
ISOLATION_NOTE = ""

bot_start_time = time.time()
START_TIME = datetime.now()

RECOMMENDED_PACKAGES = [
    "pip", "setuptools", "wheel", "requests", "numpy", "pandas", "flask",
    "aiohttp", "pyrogram", "python-dotenv", "beautifulsoup4", "lxml",
    "pillow", "matplotlib", "scipy", "scikit-learn", "pytest",
]

# ============================================================
# PREMIUM EMOJI
# ============================================================

PREMIUM_EMOJI_IDS = [
    "5289722755871162900", "5372849966689566579", "5359664288241829619",
    "5445033158456145975", "5445092669522996408", "5445358884480916784",
    "5445307250384075361", "5447602197439218445", "6147460667281511517",
    "6235459831302460476", "6244492465353529537", "6318817991102305543",
    "5231200819986047254", "5944970130554359187", "6120548140211770562",
    "4987977590812705943", "5416081784641168838", "6321171873698681876",
    "5915556996215476302", "5877443460725739250", "4990298741463319592",
    "5462956611033117422", "6231214251835397322", "6282846669335702032",
    "5210952531676504517", "6129639980387015660",
]

PE_FIRE = PREMIUM_EMOJI_IDS[0]
PE_STAR = PREMIUM_EMOJI_IDS[1]
PE_ROCKET = PREMIUM_EMOJI_IDS[2]
PE_CROWN = PREMIUM_EMOJI_IDS[3]
PE_SHIELD = PREMIUM_EMOJI_IDS[4]
PE_MONEY = PREMIUM_EMOJI_IDS[5]
PE_PHONE = PREMIUM_EMOJI_IDS[6]
PE_CHECK = PREMIUM_EMOJI_IDS[7]
PE_CROSS = PREMIUM_EMOJI_IDS[8]
PE_WARNING = PREMIUM_EMOJI_IDS[9]
PE_LOCK = PREMIUM_EMOJI_IDS[10]
PE_GIFT = PREMIUM_EMOJI_IDS[11]
PE_APPROVE = PREMIUM_EMOJI_IDS[12]
PE_USER = PREMIUM_EMOJI_IDS[13]
PE_ADMIN = PREMIUM_EMOJI_IDS[14]
PE_UPLOAD = PREMIUM_EMOJI_IDS[15]
PE_FOLDER = PREMIUM_EMOJI_IDS[16]
PE_SETTINGS = PREMIUM_EMOJI_IDS[17]
PE_SERVER = PREMIUM_EMOJI_IDS[18]
PE_DIAMOND = PREMIUM_EMOJI_IDS[19]
PE_BOT = PREMIUM_EMOJI_IDS[20]


def pe(emoji_id, fallback="💎"):
    return f'<tg-emoji emoji-id="{emoji_id}">{fallback}</tg-emoji>'


def safe_html(value):
    return html.escape(redact(value), quote=False)


def premium_header(title, emoji_id=PE_CROWN, fallback="👑"):
    return f"{pe(emoji_id, fallback)} <b>{safe_html(title)}</b>"


bot = telebot.TeleBot(BOT_TOKEN, parse_mode=None, threaded=True)

# ============================================================
# DATA
# ============================================================

def save_data():
    with data_lock:
        try:
            temp_file = DATA_FILE + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(users, f, indent=4, ensure_ascii=False)
            os.replace(temp_file, DATA_FILE)
            try:
                os.chmod(DATA_FILE, 0o600)
            except OSError:
                pass
        except Exception as e:
            log_error("Save Error", e)


def load_data():
    global users
    with data_lock:
        if not os.path.exists(DATA_FILE):
            users = {}
            return
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            users.clear()
            for key, value in raw_data.items():
                try:
                    uid = int(key)
                except Exception as e:
                    log_error("load uid", e)
                    continue
                if not isinstance(value, dict):
                    value = {}
                value.setdefault("files", [])
                value.setdefault("approved", uid == OWNER_ID)
                value.setdefault("rejected", False)
                value.setdefault("banned", False)
                value.setdefault("file_limit", DEFAULT_FILE_LIMIT)
                value.setdefault("unlimited", False)
                value.setdefault("restart", {})
                value.setdefault("limits", {})
                users[uid] = value
        except Exception as e:
            log_error("Load Error", e)
            users = {}


load_data()


def ensure_user(uid):
    if uid not in users:
        users[uid] = {
            "files": [],
            "approved": uid == OWNER_ID,
            "rejected": False,
            "banned": False,
            "file_limit": DEFAULT_FILE_LIMIT,
            "unlimited": False,
            "restart": {},
            "limits": {},
        }
        save_data()
    else:
        users[uid].setdefault("files", [])
        users[uid].setdefault("approved", uid == OWNER_ID)
        users[uid].setdefault("rejected", False)
        users[uid].setdefault("banned", False)
        users[uid].setdefault("file_limit", DEFAULT_FILE_LIMIT)
        users[uid].setdefault("unlimited", False)
        users[uid].setdefault("restart", {})
        users[uid].setdefault("limits", {})
        if uid == OWNER_ID and not users[uid]["approved"]:
            users[uid]["approved"] = True
            users[uid]["banned"] = False
            save_data()


def is_owner(uid):
    return uid == OWNER_ID


def is_approved(uid):
    if is_owner(uid):
        return True
    ensure_user(uid)
    if users[uid].get("banned"):
        return False
    return users[uid].get("approved", False)


def user_limit(uid, key, default):
    ensure_user(uid)
    if users[uid].get("unlimited") and key in ("runtime", "memory", "cpu", "pids", "concurrent"):
        return None
    custom = users[uid].get("limits", {}).get(key)
    return default if custom is None else custom


def approval_buttons(uid):
    markup = InlineKeyboardMarkup()
    markup.row(
        InlineKeyboardButton("✅ APPROVE", callback_data=f"approve_{uid}"),
        InlineKeyboardButton("❌ REJECT", callback_data=f"reject_{uid}"),
    )
    return markup


def send_approval_request(message):
    uid = message.from_user.id
    first_name = message.from_user.first_name or "Unknown"
    username = message.from_user.username
    username_text = f"@{username}" if username else "No username"
    text = (
        f"{pe(PE_ADMIN, '👑')} <b>NEW USER APPROVAL - DK HOSTING</b>\n\n"
        f"{pe(PE_USER, '👤')} <b>Name:</b> {safe_html(first_name)}\n"
        f"{pe(PE_PHONE, '🆔')} <b>User ID:</b> <code>{uid}</code>\n"
        f"{pe(PE_BOT, '🤖')} <b>Username:</b> {safe_html(username_text)}\n\n"
        f"{pe(PE_WARNING, '⚠️')} <b>Status:</b> Pending Approval"
    )
    try:
        bot.send_message(OWNER_ID, text, reply_markup=approval_buttons(uid), parse_mode="HTML")
    except Exception as e:
        log_error("Approval notification error", e)


def approval_required(message):
    uid = message.from_user.id
    if is_owner(uid):
        return False
    ensure_user(uid)
    if users[uid].get("banned"):
        bot.reply_to(
            message,
            f"{pe(PE_LOCK, '🔐')} <b>ACCESS DENIED</b>\n\nYour account is banned.",
            parse_mode="HTML",
        )
        return True
    if is_approved(uid):
        return False
    bot.reply_to(
        message,
        (
            f"{pe(PE_LOCK, '🔐')} <b>ACCESS PENDING</b>\n\n"
            f"{pe(PE_ADMIN, '👑')} Your account is waiting for <b>Owner Approval</b>.\n\n"
            f"{pe(PE_STAR, '⭐')} Please wait until the owner approves your account.\n"
            f"<b>Credit:</b> DK"
        ),
        parse_mode="HTML",
    )
    return True


def notify_owner(text, index=0):
    try:
        emoji_id = PREMIUM_EMOJI_IDS[index % len(PREMIUM_EMOJI_IDS)]
        bot.send_message(OWNER_ID, f"{pe(emoji_id, '🔔')} {redact(text)}", parse_mode="HTML")
    except Exception as e:
        log_error("Owner notification error", e)


# ============================================================
# PATH / NAME SAFETY
# ============================================================

def sanitize_filename(name):
    if not name:
        return None
    base = os.path.basename(str(name).replace("\\", "/"))
    if not base or base.startswith(".") or base in (".", ".."):
        return None
    if not SAFE_NAME.match(base):
        return None
    return base


def user_folder(uid):
    path = os.path.join(UPLOAD_DIR, str(int(uid)))
    os.makedirs(path, exist_ok=True)
    return os.path.realpath(path)


def contained(root, path):
    root_r = os.path.realpath(root)
    try:
        path_r = os.path.realpath(path)
        if os.path.commonpath([root_r, path_r]) != root_r:
            return False
    except (ValueError, OSError):
        return False
    abs_lex = os.path.abspath(path)
    try:
        if os.path.commonpath([root_r, abs_lex]) != root_r:
            return False
    except ValueError:
        return False
    return True


def safe_user_file(uid, fname):
    clean = sanitize_filename(fname)
    if not clean:
        return None
    ensure_user(uid)
    if clean not in users[uid].get("files", []):
        return None
    folder = user_folder(uid)
    path = os.path.join(folder, clean)
    if not contained(folder, path):
        return None
    if os.path.islink(path):
        return None
    return path


def file_token(uid, fname):
    raw = f"{int(uid)}:{fname}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def resolve_token(uid, token):
    if not token or not re.fullmatch(r"[a-f0-9]{16}", token):
        return None
    ensure_user(uid)
    for fname in users[uid].get("files", []):
        if file_token(uid, fname) == token:
            return fname
    return None


def folder_size(folder):
    total = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [d for d in dirnames if d != ".venv" and not d.startswith(".")]
        for name in filenames:
            fp = os.path.join(dirpath, name)
            try:
                if not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                continue
    return total


def disk_quota_bytes(uid):
    mb = user_limit(uid, "disk_mb", DEFAULT_DISK_MB)
    if mb is None:
        return None
    return int(mb) * 1024 * 1024


def upload_limit_bytes(uid):
    mb = user_limit(uid, "upload_mb", DEFAULT_UPLOAD_MB)
    if mb is None:
        return None
    return int(mb) * 1024 * 1024


# ============================================================
# REQUIREMENTS
# ============================================================

def parse_requirements(text):
    """Return (packages, error). Only plain name[extras]==/>=/<= specifiers."""
    packages = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-") or "\\" in line or "://" in line or line.startswith("git+") or line.startswith("."):
            return None, f"rejected line {lineno}"
        if any(tok in line for tok in ("://", "git+", "@ ", " file:", "\t")):
            return None, f"rejected line {lineno}"
        # bare name is allowed; comparators must match the safe pattern
        if any(op in line for op in ("==", ">=", "<=", "~=", "!=")):
            if not REQ_LINE.match(line.replace(" ", "")):
                return None, f"rejected line {lineno}"
            packages.append(line.replace(" ", ""))
        else:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?", line):
                return None, f"rejected line {lineno}"
            packages.append(line)
    return packages, None


# ============================================================
# ISOLATION
# ============================================================

def _host_tool_env():
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/tmp",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def child_env(home):
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def detect_isolation():
    forced = os.environ.get("SANDBOX_MODE", "auto").strip().lower()
    if forced == "rlimit":
        return "rlimit", "forced by SANDBOX_MODE=rlimit — path jail is NOT enforced"
    if shutil.which("docker"):
        try:
            probe = subprocess.run(
                ["docker", "info"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                env=_host_tool_env(),
            )
            if probe.returncode == 0:
                return "docker", f"docker image {DOCKER_IMAGE}; network={SANDBOX_NETWORK}"
        except Exception as e:
            log_error("docker probe", e)
    if shutil.which("bwrap"):
        return "bwrap", "bubblewrap mount namespace; other users and host data are not mounted"
    if shutil.which("firejail"):
        return "firejail", "firejail --private; weaker than docker if the profile is incomplete"
    if hasattr(os, "geteuid") and os.geteuid() == 0 and SANDBOX_UID > 0:
        return "setuid", f"setuid to {SANDBOX_UID}:{SANDBOX_GID or SANDBOX_UID}"
    return (
        "rlimit",
        "WEAK: same uid, resource limits only. A script can still read files this user can read. "
        "Install Docker or bubblewrap, or run as root with SANDBOX_UID set.",
    )


def _python_in_venv(folder):
    for rel in (os.path.join(".venv", "bin", "python"), os.path.join(".venv", "Scripts", "python.exe")):
        path = os.path.join(folder, rel)
        if os.path.isfile(path):
            return path
    return None


def ensure_venv(folder):
    py = _python_in_venv(folder)
    if py:
        return py
    venv_dir = os.path.join(folder, ".venv")
    subprocess.run(
        [sys.executable, "-m", "venv", venv_dir],
        check=True,
        timeout=180,
        env=_host_tool_env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    py = _python_in_venv(folder)
    if not py:
        raise RuntimeError("venv python missing")
    subprocess.run(
        [py, "-m", "ensurepip", "--upgrade"],
        check=False,
        timeout=180,
        env=child_env(folder),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return py


def _apply_rlimits():
    if os.name != "posix":
        return
    mapping = [
        (resource.RLIMIT_AS, LIMIT_AS_MB * 1024 * 1024),
        (resource.RLIMIT_CPU, LIMIT_CPU_SEC),
        (resource.RLIMIT_NOFILE, LIMIT_NOFILE),
        (resource.RLIMIT_FSIZE, LIMIT_FSIZE_MB * 1024 * 1024),
    ]
    # RLIMIT_NPROC is per uid. Setting it on the host uid would also cap the bot.
    if ISOLATION_MODE == "setuid":
        mapping.append((resource.RLIMIT_NPROC, LIMIT_PIDS))
    for res, value in mapping:
        try:
            resource.setrlimit(res, (value, value))
        except (ValueError, OSError):
            continue


def _preexec_setuid():
    if os.name != "posix":
        return
    os.setsid()
    if ISOLATION_MODE == "setuid" and SANDBOX_UID > 0:
        gid = SANDBOX_GID or SANDBOX_UID
        os.setgid(gid)
        os.setuid(SANDBOX_UID)
    _apply_rlimits()


def _bwrap_cmd(folder, inner, share_net=False):
    cmd = [
        "bwrap", "--die-with-parent", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-user", "--cap-drop", "ALL",
    ]
    if not share_net:
        cmd.append("--unshare-net")
    for path in ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ssl", "/etc/ca-certificates"):
        if os.path.exists(path):
            cmd += ["--ro-bind", path, path]
    cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    cmd += ["--bind", folder, folder, "--chdir", folder]
    env = child_env(folder)
    for key, val in env.items():
        cmd += ["--setenv", key, val]
    cmd.append("--")
    cmd.extend(inner)
    return cmd


def _firejail_cmd(folder, inner):
    cmd = [
        "firejail", "--quiet", f"--private={folder}", "--private-tmp",
        "--net=none", "--nonewprivs", "--caps.drop=all", "--noroot",
        f"--rlimit-as={LIMIT_AS_MB * 1024 * 1024}",
        f"--rlimit-cpu={LIMIT_CPU_SEC}",
        f"--rlimit-fsize={LIMIT_FSIZE_MB * 1024 * 1024}",
        f"--rlimit-nofile={LIMIT_NOFILE}",
        f"--rlimit-nproc={LIMIT_PIDS}",
    ]
    cmd.extend(inner)
    return cmd


def _docker_user_flag(folder):
    uid = os.getuid() if hasattr(os, "getuid") else 65534
    gid = os.getgid() if hasattr(os, "getgid") else 65534
    if uid == 0:
        try:
            os.chmod(folder, 0o777)
        except OSError:
            pass
        return "65534:65534"
    return f"{uid}:{gid}"


def _docker_cmd(folder, cname, inner, network, memory_mb, cpus, pids):
    cmd = [
        "docker", "run", "--rm", "--name", cname,
        "--network", network,
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-v", f"{os.path.realpath(folder)}:/work",
        "-w", "/work",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids or LIMIT_PIDS),
        "--memory", f"{memory_mb or LIMIT_MEMORY_MB}m",
        "--cpus", str(cpus if cpus is not None else LIMIT_CPUS),
        "--user", _docker_user_flag(folder),
    ]
    for key, val in child_env("/work").items():
        cmd += ["-e", f"{key}={val}"]
    cmd += ["-e", "PYTHONPATH=/work/.pydeps"]
    cmd.append(DOCKER_IMAGE)
    cmd.extend(inner)
    return cmd


# ============================================================
# PROCESS CONTROL
# ============================================================

def _running_count(uid):
    return sum(1 for (u, _f), rec in active_scripts.items() if u == uid and rec.get("proc") and rec["proc"].poll() is None)


def kill_record(rec):
    if not rec:
        return
    proc = rec.get("proc")
    cname = rec.get("container")
    if cname and ISOLATION_MODE == "docker":
        try:
            subprocess.run(
                ["docker", "kill", cname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                env=_host_tool_env(),
            )
        except Exception as e:
            log_error("docker kill", e)
    if not proc:
        return
    pid = proc.pid
    if os.name == "posix":
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception as e:
            log_error("killpg", e)
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except Exception as e:
                log_error("kill child", e)
        parent.kill()
    except Exception as e:
        log_error("psutil kill", e)
    try:
        proc.kill()
    except Exception as e:
        log_error("proc.kill", e)


def stop_user_script(user_id, fname):
    key = (user_id, fname)
    with state_lock:
        rec = active_scripts.get(key)
        if not rec:
            return False
        rec["stop_requested"] = True
    kill_record(rec)
    with state_lock:
        active_scripts.pop(key, None)
    return True


def stop_all_for(user_id):
    with state_lock:
        keys = [k for k in active_scripts if k[0] == user_id]
    for key in keys:
        stop_user_script(key[0], key[1])


def _append_log(key, line):
    with state_lock:
        bucket = logs_store.setdefault(key, deque(maxlen=200))
        bucket.append(redact(line)[:500])


def _launch(uid, folder, fname, unlimited):
    script_host = os.path.join(folder, fname)
    memory_mb = None if unlimited else (user_limit(uid, "memory_mb", LIMIT_MEMORY_MB) or LIMIT_MEMORY_MB)
    cpus = None if unlimited else user_limit(uid, "cpus", LIMIT_CPUS)
    pids = None if unlimited else (user_limit(uid, "pids", LIMIT_PIDS) or LIMIT_PIDS)
    cname = "dk" + hashlib.sha256(f"{uid}:{fname}:{time.time()}".encode()).hexdigest()[:20]
    popen_kwargs = dict(
        cwd=folder,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    if ISOLATION_MODE == "docker":
        cmd = _docker_cmd(folder, cname, ["python", "-u", f"/work/{fname}"], SANDBOX_NETWORK, memory_mb, cpus, pids)
        proc = subprocess.Popen(cmd, env=_host_tool_env(), **popen_kwargs)
        return proc, cname
    py = ensure_venv(folder)
    if ISOLATION_MODE == "bwrap":
        cmd = _bwrap_cmd(folder, [py, "-u", script_host], share_net=False)
        proc = subprocess.Popen(cmd, env=child_env(folder), **popen_kwargs)
        return proc, None
    if ISOLATION_MODE == "firejail":
        cmd = _firejail_cmd(folder, [py, "-u", os.path.basename(script_host)])
        proc = subprocess.Popen(cmd, env=child_env(folder), **popen_kwargs)
        return proc, None
    popen_kwargs["env"] = child_env(folder)
    popen_kwargs["preexec_fn"] = _preexec_setuid if os.name == "posix" and not unlimited else None
    proc = subprocess.Popen([py, "-u", script_host], **popen_kwargs)
    return proc, None


def run_script_thread(user_id, fname):
    key = (user_id, fname)
    folder = user_folder(user_id)
    restarts = 0
    while True:
        proc = None
        try:
            unlimited = bool(users.get(user_id, {}).get("unlimited"))
            proc, cname = _launch(user_id, folder, fname, unlimited)
            with state_lock:
                rec = active_scripts.get(key)
                if rec is None or rec.get("stop_requested"):
                    kill_record({"proc": proc, "container": cname})
                    return
                rec["proc"] = proc
                rec["container"] = cname
                rec["started"] = time.time()
            runtime = user_limit(user_id, "runtime", LIMIT_RUNTIME_SEC)
            while True:
                line = proc.stdout.readline() if proc.stdout else ""
                if line:
                    _append_log(key, line.rstrip())
                if proc.poll() is not None and not line:
                    break
                if runtime and (time.time() - active_scripts.get(key, {}).get("started", time.time())) > runtime:
                    _append_log(key, f"[limit] runtime exceeded ({runtime}s)")
                    with state_lock:
                        rec = active_scripts.get(key)
                        if rec:
                            rec["stop_requested"] = True
                    kill_record(active_scripts.get(key) or {"proc": proc, "container": cname})
                    log_meta[key] = {"exit": -9, "note": "runtime"}
                    _notify_limit(user_id, fname, "runtime")
                    return
            code = proc.wait()
            log_meta[key] = {"exit": code, "note": "exited"}
            _append_log(key, f"[exit] code {code}")
        except Exception as e:
            log_error("script thread", e)
            _append_log(key, "[error] script failed to start")
            log_meta[key] = {"exit": -1, "note": "start-failed"}
            code = -1
        finally:
            with state_lock:
                rec = active_scripts.get(key)
                if rec and rec.get("proc") is proc:
                    rec["proc"] = None
        with state_lock:
            rec = active_scripts.get(key)
            stop_requested = not rec or rec.get("stop_requested")
            want_restart = bool(users.get(user_id, {}).get("restart", {}).get(fname))
        if stop_requested or not want_restart or code == 0:
            with state_lock:
                active_scripts.pop(key, None)
            return
        restarts += 1
        if restarts > MAX_RESTARTS:
            _append_log(key, "[restart] gave up after 5")
            with state_lock:
                active_scripts.pop(key, None)
            notify_owner(f"<b>Restart limit</b>\nUser: <code>{user_id}</code>\nFile: <code>{safe_html(fname)}</code>", 4)
            return
        delay = min(32, 2 ** (restarts - 1))
        _append_log(key, f"[restart] attempt {restarts} in {delay}s")
        time.sleep(delay)


def start_script(user_id, fname):
    path = safe_user_file(user_id, fname)
    if not path or not os.path.isfile(path):
        return "missing"
    if not fname.endswith(".py"):
        return "not-python"
    cap = user_limit(user_id, "concurrent", DEFAULT_CONCURRENT)
    with state_lock:
        rec = active_scripts.get((user_id, fname))
        if rec and rec.get("proc") and rec["proc"].poll() is None:
            return "already"
        if cap is not None and _running_count(user_id) >= int(cap):
            return "busy"
        active_scripts[(user_id, fname)] = {
            "proc": None,
            "stop_requested": False,
            "container": None,
            "started": time.time(),
        }
        logs_store.setdefault((user_id, fname), deque(maxlen=200))
    threading.Thread(target=run_script_thread, args=(user_id, fname), daemon=True).start()
    return "started"


def _notify_limit(uid, fname, reason):
    notify_owner(
        f"<b>Limit violation</b>\nUser: <code>{uid}</code>\nFile: <code>{safe_html(fname)}</code>\nReason: <code>{safe_html(reason)}</code>",
        5,
    )
    try:
        bot.send_message(
            uid,
            f"{pe(PE_WARNING, '⚠️')} <b>Script stopped — limit exceeded</b>\n<code>{safe_html(fname)}</code>\n<code>{safe_html(reason)}</code>",
            parse_mode="HTML",
        )
    except Exception as e:
        log_error("limit notify user", e)


def watchdog_loop():
    while True:
        time.sleep(2)
        with state_lock:
            snapshot = list(active_scripts.items())
        for key, rec in snapshot:
            proc = rec.get("proc")
            if not proc or proc.poll() is not None:
                continue
            uid, fname = key
            if users.get(uid, {}).get("unlimited"):
                continue
            mem_mb = user_limit(uid, "memory_mb", LIMIT_MEMORY_MB) or LIMIT_MEMORY_MB
            try:
                parent = psutil.Process(proc.pid)
                rss = parent.memory_info().rss
                for child in parent.children(recursive=True):
                    try:
                        rss += child.memory_info().rss
                    except Exception:
                        continue
                nproc = 1 + len(parent.children(recursive=True))
            except Exception:
                continue
            reason = None
            if rss > int(mem_mb) * 1024 * 1024:
                reason = "memory"
            elif nproc > (user_limit(uid, "pids", LIMIT_PIDS) or LIMIT_PIDS) + 5:
                reason = "processes"
            if reason:
                with state_lock:
                    current = active_scripts.get(key)
                    if current:
                        current["stop_requested"] = True
                kill_record(current or rec)
                log_meta[key] = {"exit": -9, "note": reason}
                _append_log(key, f"[limit] killed: {reason}")
                _notify_limit(uid, fname, reason)
                with state_lock:
                    active_scripts.pop(key, None)


def pip_install(uid, packages, chat_id=None, message_id=None, description="Installing"):
    folder = user_folder(uid)
    if not packages:
        return False, "nothing to install"
    timeout = PIP_TIMEOUT
    try:
        if ISOLATION_MODE == "docker":
            cmd = _docker_cmd(
                folder,
                "dkpip" + hashlib.sha256(f"{uid}:{time.time()}".encode()).hexdigest()[:16],
                ["python", "-m", "pip", "install", "--no-input", "--disable-pip-version-check",
                 "--timeout", "60", "--target", "/work/.pydeps"] + packages,
                "bridge",
                LIMIT_MEMORY_MB,
                LIMIT_CPUS,
                LIMIT_PIDS,
            )
            proc = subprocess.Popen(
                cmd, cwd=folder, env=_host_tool_env(),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        else:
            py = ensure_venv(folder)
            inner = [py, "-m", "pip", "install", "--no-input", "--disable-pip-version-check",
                     "--timeout", "60"] + packages
            if ISOLATION_MODE == "bwrap":
                cmd = _bwrap_cmd(folder, inner, share_net=True)
            else:
                cmd = inner
            proc = subprocess.Popen(
                cmd, cwd=folder, env=child_env(folder),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        log_error("pip timeout", e)
        try:
            kill_record({"proc": proc, "container": None})
        except Exception as kill_err:
            log_error("pip kill", kill_err)
        return False, "pip timed out"
    except Exception as e:
        log_error("pip install", e)
        return False, "pip failed"
    text = redact(out or "")
    tail = "\n".join(text.splitlines()[-12:]) or "Completed."
    ok = proc.returncode == 0
    if chat_id and message_id:
        try:
            bot.edit_message_text(
                (
                    f"{pe(PE_CHECK, '✅') if ok else pe(PE_CROSS, '❌')} <b>{safe_html(description)}</b>\n\n"
                    f"<pre>{safe_html(tail[-3000:])}</pre>"
                ),
                chat_id=chat_id,
                message_id=message_id,
                parse_mode="HTML",
            )
        except Exception as e:
            log_error("pip edit", e)
    return ok, tail


def install_requirements_file(uid, folder, chat_id=None, message_id=None):
    req = os.path.join(folder, "requirements.txt")
    if not os.path.isfile(req) or os.path.islink(req) or not contained(folder, req):
        return
    try:
        with open(req, "r", encoding="utf-8", errors="replace") as f:
            text = f.read(64_000)
    except Exception as e:
        log_error("read requirements", e)
        return
    packages, err = parse_requirements(text)
    if err:
        if chat_id and message_id:
            try:
                bot.edit_message_text(
                    f"{pe(PE_CROSS, '❌')} <b>requirements.txt rejected</b>\nUnsafe pip options, URLs, or local paths are not allowed.",
                    chat_id=chat_id, message_id=message_id, parse_mode="HTML",
                )
            except Exception as e:
                log_error("req reject edit", e)
        notify_owner(f"<b>Rejected requirements</b>\nUser: <code>{uid}</code>", 6)
        return
    if packages:
        pip_install(uid, packages, chat_id, message_id, "Requirements installed")


def install_recommended_packages(uid, chat_id, message_id):
    ok, _tail = pip_install(uid, list(RECOMMENDED_PACKAGES), chat_id, message_id, "Recommended packages")
    if not ok:
        _log.error("recommended install failed for uid %s", uid)


# ============================================================
# ZIP
# ============================================================

def _is_zip_symlink(info):
    mode = (info.external_attr >> 16) & 0o170000
    return mode == 0o120000


def safe_extract_zip(uid, zip_path, folder):
    quota = disk_quota_bytes(uid)
    used = folder_size(folder)
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > ZIP_MAX_FILES:
            raise ValueError("too many files in zip")
        total = 0
        compressed = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or name.startswith("../") or "/../" in f"/{name}/" or name.startswith("~"):
                raise ValueError("unsafe path in zip")
            if _is_zip_symlink(info):
                raise ValueError("symlink in zip")
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if not parts or any(p == ".." or p.startswith(".") for p in parts):
                raise ValueError("unsafe path in zip")
            dest = os.path.realpath(os.path.join(folder, *parts))
            if os.path.commonpath([os.path.realpath(folder), dest]) != os.path.realpath(folder):
                raise ValueError("zip escapes user folder")
            total += info.file_size
            compressed += max(info.compress_size, 1)
            if info.file_size > (upload_limit_bytes(uid) or DEFAULT_UPLOAD_MB * 1024 * 1024):
                raise ValueError("zip member too large")
        if compressed and (total / compressed) > ZIP_MAX_RATIO and total > 1_000_000:
            raise ValueError("zip compression ratio rejected")
        if quota is not None and used + total > quota:
            raise ValueError("zip would exceed disk quota")
        extracted = []
        for info in infos:
            if info.is_dir():
                continue
            parts = [p for p in info.filename.replace("\\", "/").split("/") if p not in ("", ".")]
            dest = os.path.join(folder, *parts)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with zf.open(info, "r") as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
            extracted.append(parts)
    return extracted


# ============================================================
# UI
# ============================================================

def uptime():
    seconds = int(time.time() - bot_start_time)
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m {seconds % 60}s"


def get_system_info():
    cpu_freq = psutil.cpu_freq()
    cpu_ghz = (cpu_freq.current / 1000) if cpu_freq else 0
    ram = psutil.virtual_memory()
    return cpu_ghz, ram.total / (1024 ** 3), ram.available / (1024 ** 3)


def control_buttons(uid=None):
    markup = ReplyKeyboardMarkup(resize_keyboard=True)
    markup.row(KeyboardButton("🌏 Upload"), KeyboardButton("📁 𝐌𝐲 𝐅𝐢𝐥𝐞𝐬"))
    markup.row(KeyboardButton("🔄 𝐑𝐞𝐬𝐭𝐚𝐫𝐭"), KeyboardButton("⏹ 𝐒𝐭𝐨𝐩"))
    markup.row(KeyboardButton("⚡ 𝐒𝐩𝐞𝐞𝐝"), KeyboardButton("🚀 𝐒𝐭𝐚𝐭ᴜѕ"))
    if uid and is_owner(uid):
        markup.row(KeyboardButton("⚙️ Recommended Install"))
        markup.row(KeyboardButton("👑 Admin Panel"))
    return markup


def admin_panel_markup():
    markup = InlineKeyboardMarkup()
    markup.row(
        InlineKeyboardButton("👥 All Users", callback_data="admin_users"),
        InlineKeyboardButton("⏳ Pending Users", callback_data="admin_pending"),
    )
    markup.row(
        InlineKeyboardButton("🟢 Running Scripts", callback_data="admin_running"),
        InlineKeyboardButton("🛑 Stop All Scripts", callback_data="admin_stop_all"),
    )
    markup.row(
        InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast"),
        InlineKeyboardButton("📦 Pip Install", callback_data="admin_pip"),
    )
    return markup


def get_admin_panel_text():
    total_users = len(users)
    approved_users = sum(1 for u in users.values() if u.get("approved", False))
    pending_users = sum(1 for u in users.values() if not u.get("approved", False) and not u.get("rejected", False) and not u.get("banned", False))
    total_files = sum(len(u.get("files", [])) for u in users.values())
    with state_lock:
        running_scripts = sum(1 for rec in active_scripts.values() if rec.get("proc") and rec["proc"].poll() is None)
    return (
        f"┏━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
        f"┃ {pe(PE_ADMIN, '👑')} <b>DK HOSTING ADMIN PANEL</b> ┃\n"
        f"┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n"
        f"👥 <b>Total Users:</b> <code>{total_users}</code>\n"
        f"✅ <b>Approved Users:</b> <code>{approved_users}</code>\n"
        f"⏳ <b>Pending Users:</b> <code>{pending_users}</code>\n"
        f"📁 <b>Total Uploaded Files:</b> <code>{total_files}</code>\n"
        f"🟢 <b>Active Scripts:</b> <code>{running_scripts}</code>\n"
        f"⏱️ <b>Uptime:</b> <code>{uptime()}</code>\n"
        f"🧱 <b>Isolation:</b> <code>{safe_html(ISOLATION_MODE)}</code>\n\n"
        f"✨ <b>Credit:</b> DK"
    )


def _usage_text(uid):
    folder = user_folder(uid)
    disk = folder_size(folder)
    rss = 0
    with state_lock:
        recs = [active_scripts[k] for k in active_scripts if k[0] == uid]
    for rec in recs:
        proc = rec.get("proc")
        if not proc or proc.poll() is not None:
            continue
        try:
            parent = psutil.Process(proc.pid)
            rss += parent.memory_info().rss
            for child in parent.children(recursive=True):
                try:
                    rss += child.memory_info().rss
                except Exception:
                    continue
        except Exception:
            continue
    return disk, rss


# ============================================================
# COMMANDS
# ============================================================

@bot.message_handler(commands=["start"])
def start_command(message):
    uid = message.from_user.id
    first_name = message.from_user.first_name or "User"
    is_new = uid not in users
    ensure_user(uid)
    if is_owner(uid):
        users[uid]["approved"] = True
        users[uid]["rejected"] = False
        users[uid]["banned"] = False
        save_data()
    if is_new and not is_owner(uid):
        send_approval_request(message)
        bot.send_message(
            uid,
            (
                f"{pe(PE_LOCK, '🔐')} <b>ACCESS REQUESTED</b>\n\n"
                f"{pe(PE_USER, '👤')} Welcome, <b>{safe_html(first_name)}</b>!\n\n"
                f"{pe(PE_ADMIN, '👑')} Your access request has been sent to the owner.\n\n"
                f"{pe(PE_STAR, '⭐')} <b>Please wait for approval.</b>\n"
                f"💎 <b>Powered by:</b> DK HOSTING"
            ),
            parse_mode="HTML",
        )
        return
    if not is_approved(uid):
        bot.send_message(
            uid,
            (
                f"{pe(PE_LOCK, '🔐')} <b>ACCESS PENDING</b>\n\n"
                f"Your account is waiting for <b>Owner Approval</b>.\n\n"
                f"{pe(PE_STAR, '⭐')} Please wait.\n"
                f"💎 <b>Powered by:</b> DK HOSTING"
            ),
            parse_mode="HTML",
        )
        return
    welcome = (
        f"┏━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
        f"┃ {pe(PE_ROCKET, '🚀')} <b>DK HOSTING</b> ┃\n"
        f"┃ <b>VERSION 0.3 | CREDIT: DK</b> ┃\n"
        f"┗━━━━━━━━━━━━━━━━━━━━━━━━┛\n\n"
        f"{pe(PE_GIFT, '👤')} <b>Wᴇʟᴄᴏᴍᴇ</b> {safe_html(first_name)}!\n\n"
        f"{pe(PE_PHONE, '🆔')} <b>Uꜱᴇʀ ID:</b> <code>{uid}</code>\n\n"
        f"{pe(PE_FOLDER, '📁')} <b>Fɪʟᴇꜱ:</b> {len(users[uid]['files'])}\n\n"
        f"{pe(PE_STAR, '⚡')} <b>Fᴇᴀᴛᴜʀᴇꜱ:</b>\n"
        f"• {pe(PE_CHECK, '✅')} Aᴜᴛᴏ-Rᴇᴄᴏᴠᴇʀʏ Sʏꜱᴛᴇᴍ\n"
        f"• {pe(PE_BOT, '🤖')} Pʏᴛʜᴏɴ / Zɪᴘ / Tхᴛ Sᴜᴘᴘᴏʀᴛ\n"
        f"• {pe(PE_DIAMOND, '💎')} Pʀᴇᴍɪᴜᴍ Eᴍᴏᴊɪ Sʏꜱᴛᴇᴍ\n"
        f"• {pe(PE_CROWN, '👑')} Dᴇᴠᴇʟᴏᴘᴇʀ & Cʀᴇᴅɪᴛ: <b>DK</b>\n\n"
        f"Uꜱᴇ ᴛʜᴇ Bᴜᴛᴛᴏɴs Bᴇʟᴏᴡ."
    )
    bot.send_message(uid, welcome, reply_markup=control_buttons(uid), parse_mode="HTML")
    if not is_owner(uid):
        notify_owner(f"<b>User Started Bot</b>\n👤 <code>{uid}</code>\nName: {safe_html(first_name)}", 0)


@bot.message_handler(commands=["admin"])
def admin_command(message):
    if not is_owner(message.from_user.id):
        bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Access Denied! Owner Only.</b>", parse_mode="HTML")
        return
    bot.send_message(message.from_user.id, get_admin_panel_text(), reply_markup=admin_panel_markup(), parse_mode="HTML")


@bot.message_handler(commands=["running", "kill", "ban", "unban", "setlimit", "usage", "unlimited"])
def owner_commands(message):
    uid = message.from_user.id
    if not is_owner(uid):
        bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Access Denied! Owner Only.</b>", parse_mode="HTML")
        return
    parts = (message.text or "").split()
    cmd = parts[0].split("@", 1)[0].lower()
    try:
        if cmd == "/running":
            lines = ["🟢 <b>ACTIVE RUNNING SCRIPTS:</b>\n"]
            with state_lock:
                items = [(u, f) for (u, f), rec in active_scripts.items() if rec.get("proc") and rec["proc"].poll() is None]
            if not items:
                lines.append("No scripts currently running.")
            for u, f in items:
                lines.append(f"• User <code>{u}</code>: <code>{safe_html(f)}</code>")
            bot.reply_to(message, "\n".join(lines), parse_mode="HTML")
            return
        if cmd == "/kill" and len(parts) >= 3:
            target = int(parts[1])
            fname = sanitize_filename(parts[2])
            if fname and stop_user_script(target, fname):
                bot.reply_to(message, f"🛑 Stopped <code>{safe_html(fname)}</code> for <code>{target}</code>", parse_mode="HTML")
            else:
                bot.reply_to(message, "❌ Script is not running.")
            return
        if cmd == "/ban" and len(parts) >= 2:
            target = int(parts[1])
            if target == OWNER_ID:
                bot.reply_to(message, "❌ Cannot ban the owner.")
                return
            ensure_user(target)
            users[target]["banned"] = True
            users[target]["approved"] = False
            save_data()
            stop_all_for(target)
            bot.reply_to(message, f"🚫 Banned <code>{target}</code> and stopped their scripts.", parse_mode="HTML")
            return
        if cmd == "/unban" and len(parts) >= 2:
            target = int(parts[1])
            ensure_user(target)
            users[target]["banned"] = False
            users[target]["rejected"] = False
            save_data()
            bot.reply_to(message, f"✅ Unbanned <code>{target}</code>. Approve them before they can run scripts.", parse_mode="HTML")
            return
        if cmd == "/setlimit" and len(parts) >= 4:
            target = int(parts[1])
            key = parts[2]
            value = parts[3]
            allowed = {"file_limit", "concurrent", "disk_mb", "upload_mb", "runtime", "memory_mb", "pids"}
            if key not in allowed:
                bot.reply_to(message, "Keys: " + ", ".join(sorted(allowed)))
                return
            ensure_user(target)
            number = int(value)
            if key == "file_limit":
                users[target]["file_limit"] = number
            else:
                users[target]["limits"][key] = number
            save_data()
            bot.reply_to(message, f"✅ <code>{safe_html(key)}</code> for <code>{target}</code> set to <code>{number}</code>", parse_mode="HTML")
            return
        if cmd == "/unlimited" and len(parts) >= 3:
            target = int(parts[1])
            flag = parts[2].lower() in ("1", "on", "yes", "true")
            ensure_user(target)
            users[target]["unlimited"] = flag
            save_data()
            bot.reply_to(message, f"✅ unlimited={'on' if flag else 'off'} for <code>{target}</code>", parse_mode="HTML")
            return
        if cmd == "/usage" and len(parts) >= 2:
            target = int(parts[1])
            ensure_user(target)
            disk, rss = _usage_text(target)
            bot.reply_to(
                message,
                (
                    f"👤 <code>{target}</code>\n"
                    f"💾 Disk: <code>{disk / (1024 * 1024):.2f} MB</code>\n"
                    f"🧠 Script RSS: <code>{rss / (1024 * 1024):.2f} MB</code>\n"
                    f"🟢 Running: <code>{_running_count(target)}</code>\n"
                    f"🧱 Isolation: <code>{safe_html(ISOLATION_MODE)}</code>"
                ),
                parse_mode="HTML",
            )
            return
    except Exception as e:
        log_error("owner command", e)
        bot.reply_to(message, "❌ Command failed.")
        return
    bot.reply_to(
        message,
        "Usage:\n/running\n/kill <uid> <file>\n/ban <uid>\n/unban <uid>\n/setlimit <uid> <key> <n>\n/unlimited <uid> on|off\n/usage <uid>",
    )


@bot.message_handler(func=lambda message: True, content_types=["text"])
def control_handler(message):
    uid = message.from_user.id
    text = (message.text or "").strip()
    ensure_user(uid)
    if is_owner(uid) and uid in admin_states:
        state = admin_states.pop(uid)
        if text.lower() == "/cancel":
            bot.reply_to(message, "✅ Action cancelled.")
            return
        if state == "broadcast":
            sent = 0
            failed = 0
            for target_uid in list(users.keys()):
                try:
                    bot.send_message(
                        target_uid,
                        f"📢 <b>ANNOUNCEMENT FROM DK HOSTING</b>\n\n{safe_html(text)}",
                        parse_mode="HTML",
                    )
                    sent += 1
                except Exception as e:
                    log_error("broadcast", e)
                    failed += 1
            bot.reply_to(
                message,
                f"✅ <b>Broadcast Completed!</b>\nSent: <code>{sent}</code> | Failed: <code>{failed}</code>",
                parse_mode="HTML",
            )
            return
        if state == "pip_install":
            packages, err = parse_requirements(text)
            if err or not packages:
                bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Package spec rejected.</b> Plain names only.", parse_mode="HTML")
                return
            msg = bot.reply_to(message, f"📥 <b>Installing <code>{safe_html(text)}</code>...</b>", parse_mode="HTML")
            threading.Thread(
                target=pip_install,
                args=(uid, packages, message.chat.id, msg.message_id, f"Package {text}"),
                daemon=True,
            ).start()
            return
    if approval_required(message):
        return
    user_data = users[uid]
    if text.startswith("🌏"):
        limit = "Unlimited (Owner)" if is_owner(uid) else user_data.get("file_limit", DEFAULT_FILE_LIMIT)
        bot.reply_to(
            message,
            (
                f"{pe(PE_UPLOAD, '📤')} <b>UPLOAD YOUR FILES</b>\n\n"
                f"Send any of the following files directly to this chat:\n"
                f"• <code>.py</code> (Python Script - Auto Runs)\n"
                f"• <code>.txt</code> (requirements.txt - Auto Installs)\n"
                f"• <code>.zip</code> (Project Archive - Auto Extracts)\n\n"
                f"📁 <b>Your Current Files:</b> <code>{len(user_data['files'])} / {limit}</code>\n"
                f"👑 <b>DK HOSTING</b>"
            ),
            parse_mode="HTML",
        )
    elif text.startswith("📁"):
        _send_file_list(message.chat.id, uid, reply_to=message)
    elif text.startswith("⚡"):
        start_time = time.time()
        time.sleep(0.05)
        processing_time = time.time() - start_time
        cpu_ghz, total_ram_gb, free_ram_gb = get_system_info()
        bot.reply_to(
            message,
            (
                f"{pe(PE_FIRE, '⚡')} <b>DK HOSTING SPEED</b>\n\n"
                f"⏱️ <b>Response:</b> {round(processing_time, 4)} sec\n\n"
                f"⚙️ <b>CPU:</b> {round(cpu_ghz, 2)} GHz\n"
                f"💾 <b>RAM:</b> {round(total_ram_gb, 2)} GB\n"
                f"🟢 <b>FREE:</b> {round(free_ram_gb, 2)} GB\n\n"
                f"👑 <b>Credit:</b> DK"
            ),
            parse_mode="HTML",
        )
    elif text.startswith("🔄"):
        stop_all_for(uid)
        restarted_count = 0
        for fname in list(user_data["files"]):
            if fname.endswith(".py") and os.path.isfile(os.path.join(user_folder(uid), fname)):
                if start_script(uid, fname) == "started":
                    restarted_count += 1
                    time.sleep(1)
        bot.reply_to(
            message,
            f"{pe(PE_ROCKET, '🔄')} <b>All your scripts ({restarted_count}) have been restarted!</b>",
            parse_mode="HTML",
        )
    elif text.startswith("⏹"):
        stop_all_for(uid)
        bot.reply_to(message, f"{pe(PE_SHIELD, '⏹')} <b>Stopped all your running scripts.</b>", parse_mode="HTML")
    elif text.startswith("🚀"):
        total_users = len(users)
        total_files = sum(len(u.get("files", [])) for u in users.values() if u)
        with state_lock:
            running_scripts = sum(1 for rec in active_scripts.values() if rec.get("proc") and rec["proc"].poll() is None)
        approved_users = sum(1 for u in users.values() if u.get("approved", False))
        pending_users = sum(1 for u in users.values() if not u.get("approved", False) and not u.get("rejected", False))
        uptime_seconds = (datetime.now() - START_TIME).total_seconds()
        hours, remainder = divmod(int(uptime_seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        bot.reply_to(
            message,
            (
                f"📊 <b>DK HOSTING LIVE STATISTICS</b>\n\n"
                f"👥 <b>Total Users:</b> {total_users}\n"
                f"✅ <b>Approved Users:</b> {approved_users}\n"
                f"⏳ <b>Pending Users:</b> {pending_users}\n"
                f"📁 <b>Total Files:</b> {total_files}\n"
                f"🟢 <b>Running Scripts:</b> {running_scripts}\n"
                f"🔒 <b>Bot Status:</b> {pe(PE_CHECK, '🟢')} <b>ONLINE</b>\n\n"
                f"⏱️ <b>Uptime:</b> {hours}h {minutes}m {seconds}s\n"
                f"👑 <b>Credit:</b> DK"
            ),
            parse_mode="HTML",
        )
    elif text.startswith("⚙️"):
        if not is_owner(uid):
            bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Owner only!</b>", parse_mode="HTML")
            return
        msg = bot.reply_to(
            message,
            f"{pe(PE_SETTINGS, '⚙️')} <b>Starting Recommended Packages Installation...</b>",
            parse_mode="HTML",
        )
        threading.Thread(
            target=install_recommended_packages,
            args=(uid, message.chat.id, msg.message_id),
            daemon=True,
        ).start()
    elif text.startswith("👑"):
        if not is_owner(uid):
            bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Owner only!</b>", parse_mode="HTML")
            return
        bot.send_message(uid, get_admin_panel_text(), reply_markup=admin_panel_markup(), parse_mode="HTML")


def _file_buttons(uid):
    buttons = []
    for fname in users[uid]["files"]:
        buttons.append([InlineKeyboardButton(f"📄 {fname}", callback_data=f"file_{file_token(uid, fname)}")])
    return buttons


def _send_file_list(chat_id, uid, reply_to=None, edit=None):
    files = users[uid]["files"]
    if not files:
        text = f"{pe(PE_CROSS, '❌')} <b>No files uploaded yet. Send a .py or .zip file!</b>"
        if edit:
            bot.edit_message_text(text, chat_id=edit[0], message_id=edit[1], parse_mode="HTML")
        else:
            bot.reply_to(reply_to, text, parse_mode="HTML")
        return
    text = f"{pe(PE_FOLDER, '📁')} <b>𝐘𝐨𝐮𝐫 𝐅𝐢𝐥𝐞𝐬 (DK HOSTING):</b>"
    markup = InlineKeyboardMarkup(_file_buttons(uid))
    if edit:
        bot.edit_message_text(text, chat_id=edit[0], message_id=edit[1], reply_markup=markup, parse_mode="HTML")
    else:
        bot.reply_to(reply_to, text, reply_markup=markup, parse_mode="HTML")


# ============================================================
# UPLOADS
# ============================================================

@bot.message_handler(content_types=["document"])
def document_handler(message):
    uid = message.from_user.id
    ensure_user(uid)
    if approval_required(message):
        return
    user_data = users[uid]
    file_limit = user_data.get("file_limit", DEFAULT_FILE_LIMIT)
    doc = message.document
    filename = sanitize_filename(getattr(doc, "file_name", None))
    if not filename or not filename.lower().endswith((".py", ".zip", ".txt")):
        bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Only .py, .zip and .txt files are allowed.</b>", parse_mode="HTML")
        return
    if not is_owner(uid) and filename not in user_data["files"] and len(user_data["files"]) >= file_limit:
        bot.reply_to(
            message,
            (
                f"{pe(PE_WARNING, '⚠️')} <b>You have reached the limit of {file_limit} files.</b>\n\n"
                f"Delete an old file from <b>📁 My Files</b> or contact the owner (DK) for more."
            ),
            parse_mode="HTML",
        )
        return
    folder = user_folder(uid)
    save_path = os.path.join(folder, filename)
    if not contained(folder, save_path):
        bot.reply_to(message, f"{pe(PE_CROSS, '❌')} <b>Rejected file name.</b>", parse_mode="HTML")
        return
    with state_lock:
        running = (uid, filename) in active_scripts and active_scripts[(uid, filename)].get("proc") and active_scripts[(uid, filename)]["proc"].poll() is None
    if running:
        bot.reply_to(message, f"{pe(PE_WARNING, '⚠️')} <b>That script is running. Stop it before replacing it.</b>", parse_mode="HTML")
        return
    max_bytes = upload_limit_bytes(uid)
    if max_bytes is not None and doc.file_size and doc.file_size > max_bytes:
        bot.reply_to(message, f"{pe(PE_WARNING, '⚠️')} <b>File exceeds the upload limit.</b>", parse_mode="HTML")
        return
    quota = disk_quota_bytes(uid)
    if quota is not None and doc.file_size and folder_size(folder) + doc.file_size > quota:
        bot.reply_to(message, f"{pe(PE_WARNING, '⚠️')} <b>Disk quota exceeded.</b>", parse_mode="HTML")
        return
    msg = bot.reply_to(message, f"{pe(PE_UPLOAD, '⬇️')} <b>Downloading {safe_html(filename)}...</b>", parse_mode="HTML")
    try:
        file_info = bot.get_file(doc.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        if max_bytes is not None and len(downloaded_file) > max_bytes:
            raise ValueError("upload too large")
        if quota is not None and folder_size(folder) + len(downloaded_file) > quota:
            raise ValueError("quota")
        with open(save_path, "wb") as f:
            f.write(downloaded_file)
    except Exception as e:
        log_error("download", e)
        bot.edit_message_text(
            f"{pe(PE_CROSS, '❌')} <b>Download failed.</b>",
            chat_id=message.chat.id,
            message_id=msg.message_id,
            parse_mode="HTML",
        )
        return
    if filename not in user_data["files"]:
        user_data["files"].append(filename)
        save_data()
    if filename.lower().endswith(".zip"):
        try:
            extracted = safe_extract_zip(uid, save_path, folder)
            for parts in extracted:
                if len(parts) == 1 and parts[0].endswith(".py"):
                    clean = sanitize_filename(parts[0])
                    if clean and clean not in user_data["files"]:
                        if is_owner(uid) or len(user_data["files"]) < file_limit:
                            user_data["files"].append(clean)
            save_data()
            bot.edit_message_text(
                f"{pe(PE_CHECK, '📦')} <b>ZIP extracted & requirements checked successfully!</b>",
                chat_id=message.chat.id,
                message_id=msg.message_id,
                parse_mode="HTML",
            )
            if os.path.isfile(os.path.join(folder, "requirements.txt")):
                threading.Thread(
                    target=install_requirements_file,
                    args=(uid, folder, message.chat.id, msg.message_id),
                    daemon=True,
                ).start()
        except Exception as e:
            log_error("zip", e)
            bot.edit_message_text(
                f"{pe(PE_CROSS, '❌')} <b>ZIP extraction failed.</b>\n\n<code>{safe_html(type(e).__name__)}</code>",
                chat_id=message.chat.id,
                message_id=msg.message_id,
                parse_mode="HTML",
            )
    elif filename.lower().endswith(".txt"):
        if filename == "requirements.txt":
            bot.edit_message_text(
                f"{pe(PE_SETTINGS, '⚙️')} <b>Installing requirements from {safe_html(filename)}...</b>",
                chat_id=message.chat.id,
                message_id=msg.message_id,
                parse_mode="HTML",
            )
            threading.Thread(
                target=install_requirements_file,
                args=(uid, folder, message.chat.id, msg.message_id),
                daemon=True,
            ).start()
        else:
            bot.edit_message_text(
                f"{pe(PE_CHECK, '✅')} <b>Stored {safe_html(filename)}.</b>",
                chat_id=message.chat.id,
                message_id=msg.message_id,
                parse_mode="HTML",
            )
    elif filename.lower().endswith(".py"):
        status = start_script(uid, filename)
        if status == "already":
            note = "Already running."
        elif status == "busy":
            note = "Concurrent script limit reached."
        elif status == "started":
            note = "Use <b>📁 My Files</b> to check logs or stop it."
        else:
            note = "Could not start."
        bot.edit_message_text(
            f"{pe(PE_ROCKET, '⚡')} <b>Started <code>{safe_html(filename)}</code> on DK HOSTING!</b>\n{note}",
            chat_id=message.chat.id,
            message_id=msg.message_id,
            parse_mode="HTML",
        )
    notify_owner(
        f"<b>File Uploaded</b>\n{pe(PE_USER, '👤')} User: <code>{uid}</code>\n{pe(PE_FOLDER, '📁')} File: <code>{safe_html(filename)}</code>",
        1,
    )


# ============================================================
# CALLBACKS
# ============================================================

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    uid = call.from_user.id
    ensure_user(uid)
    data = call.data or ""

    if data.startswith("approve_") or data.startswith("reject_") or data.startswith("admin_"):
        if not is_owner(uid):
            bot.answer_callback_query(call.id, "❌ Owner only!")
            return

    if data.startswith("approve_"):
        try:
            target_id = int(data.split("_", 1)[1])
        except Exception as e:
            log_error("approve id", e)
            bot.answer_callback_query(call.id, "❌ Invalid user ID.")
            return
        ensure_user(target_id)
        users[target_id]["approved"] = True
        users[target_id]["rejected"] = False
        users[target_id]["banned"] = False
        save_data()
        bot.answer_callback_query(call.id, "✅ User Approved!")
        try:
            bot.edit_message_text(
                (
                    f"{pe(PE_APPROVE, '✅')} <b>USER APPROVED</b>\n\n"
                    f"{pe(PE_USER, '👤')} <b>User ID:</b> <code>{target_id}</code>\n\n"
                    f"{pe(PE_ADMIN, '👑')} Approved by Owner (DK)."
                ),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode="HTML",
            )
        except Exception as e:
            log_error("approve edit", e)
        try:
            bot.send_message(
                target_id,
                (
                    f"{pe(PE_GIFT, '🎁')} <b>ACCESS APPROVED!</b>\n\n"
                    f"{pe(PE_CHECK, '✅')} Your account has been approved by the owner.\n\n"
                    f"{pe(PE_ROCKET, '🚀')} You can now use <b>DK HOSTING</b>."
                ),
                reply_markup=control_buttons(target_id),
                parse_mode="HTML",
            )
        except Exception as e:
            log_error("Approval notification error", e)
        return

    if data.startswith("reject_"):
        try:
            target_id = int(data.split("_", 1)[1])
        except Exception as e:
            log_error("reject id", e)
            bot.answer_callback_query(call.id, "❌ Invalid user ID.")
            return
        if target_id == OWNER_ID:
            bot.answer_callback_query(call.id, "❌ Cannot reject the owner.")
            return
        ensure_user(target_id)
        users[target_id]["approved"] = False
        users[target_id]["rejected"] = True
        save_data()
        stop_all_for(target_id)
        bot.answer_callback_query(call.id, "❌ User Rejected!")
        try:
            bot.edit_message_text(
                (
                    f"{pe(PE_CROSS, '❌')} <b>USER REJECTED</b>\n\n"
                    f"{pe(PE_USER, '👤')} <b>User ID:</b> <code>{target_id}</code>\n\n"
                    f"{pe(PE_ADMIN, '👑')} Rejected by Owner (DK)."
                ),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                parse_mode="HTML",
            )
        except Exception as e:
            log_error("reject edit", e)
        try:
            bot.send_message(
                target_id,
                f"{pe(PE_CROSS, '❌')} <b>ACCESS REJECTED</b>\n\nYour request was rejected by the owner.",
                parse_mode="HTML",
            )
        except Exception as e:
            log_error("reject notify", e)
        return

    if data.startswith("admin_"):
        if data == "admin_home":
            bot.edit_message_text(
                get_admin_panel_text(),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=admin_panel_markup(),
                parse_mode="HTML",
            )
            return
        if data == "admin_users":
            markup = InlineKeyboardMarkup()
            for u_id, u_info in list(users.items())[:25]:
                status_icon = "✅" if u_info.get("approved") else ("🚫" if u_info.get("banned") else ("❌" if u_info.get("rejected") else "⏳"))
                markup.row(InlineKeyboardButton(
                    f"{status_icon} User {u_id} ({len(u_info.get('files', []))} files)",
                    callback_data=f"admin_uview_{u_id}",
                ))
            markup.row(InlineKeyboardButton("⬅ Back to Admin Panel", callback_data="admin_home"))
            bot.edit_message_text(
                "👥 <b>ALL USERS LIST (Click to Manage):</b>",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=markup,
                parse_mode="HTML",
            )
            return
        if data.startswith("admin_uview_"):
            try:
                target_id = int(data.split("_")[2])
            except Exception as e:
                log_error("uview", e)
                bot.answer_callback_query(call.id, "❌ Invalid user.")
                return
            ensure_user(target_id)
            u_info = users[target_id]
            if u_info.get("banned"):
                status = "Banned 🚫"
            elif u_info.get("approved"):
                status = "Approved ✅"
            elif u_info.get("rejected"):
                status = "Rejected ❌"
            else:
                status = "Pending ⏳"
            disk, rss = _usage_text(target_id)
            markup = InlineKeyboardMarkup()
            markup.row(
                InlineKeyboardButton("✅ Approve", callback_data=f"approve_{target_id}"),
                InlineKeyboardButton("❌ Block/Reject", callback_data=f"reject_{target_id}"),
            )
            markup.row(
                InlineKeyboardButton("➕ Limit +2", callback_data=f"admin_limit_{target_id}"),
                InlineKeyboardButton("🛑 Stop Scripts", callback_data=f"admin_ustop_{target_id}"),
            )
            markup.row(
                InlineKeyboardButton("🚫 Ban", callback_data=f"admin_ban_{target_id}"),
                InlineKeyboardButton("✅ Unban", callback_data=f"admin_unban_{target_id}"),
            )
            markup.row(InlineKeyboardButton("⬅ Back to Users", callback_data="admin_users"))
            bot.edit_message_text(
                (
                    f"👤 <b>USER MANAGEMENT</b>\n\n"
                    f"🆔 <b>User ID:</b> <code>{target_id}</code>\n"
                    f"📌 <b>Status:</b> {status}\n"
                    f"📁 <b>Files:</b> <code>{len(u_info.get('files', []))} / {u_info.get('file_limit', DEFAULT_FILE_LIMIT)}</code>\n"
                    f"🟢 <b>Running Scripts:</b> <code>{_running_count(target_id)}</code>\n"
                    f"💾 <b>Disk:</b> <code>{disk / (1024 * 1024):.2f} MB</code>\n"
                    f"🧠 <b>RSS:</b> <code>{rss / (1024 * 1024):.2f} MB</code>"
                ),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=markup,
                parse_mode="HTML",
            )
            return
        if data.startswith("admin_limit_"):
            target_id = int(data.split("_")[2])
            ensure_user(target_id)
            users[target_id]["file_limit"] = users[target_id].get("file_limit", DEFAULT_FILE_LIMIT) + 2
            save_data()
            bot.answer_callback_query(call.id, f"✅ Limit increased to {users[target_id]['file_limit']}!")
            return
        if data.startswith("admin_ustop_"):
            target_id = int(data.split("_")[2])
            stop_all_for(target_id)
            bot.answer_callback_query(call.id, "🛑 Stopped user's running scripts!")
            notify_owner(f"<b>Owner stopped scripts</b>\nUser: <code>{target_id}</code>", 3)
            return
        if data.startswith("admin_ban_"):
            target_id = int(data.split("_")[2])
            if target_id == OWNER_ID:
                bot.answer_callback_query(call.id, "❌ Cannot ban the owner.")
                return
            ensure_user(target_id)
            users[target_id]["banned"] = True
            users[target_id]["approved"] = False
            save_data()
            stop_all_for(target_id)
            bot.answer_callback_query(call.id, "🚫 User banned.")
            notify_owner(f"<b>User banned</b>\nUser: <code>{target_id}</code>", 7)
            return
        if data.startswith("admin_unban_"):
            target_id = int(data.split("_")[2])
            ensure_user(target_id)
            users[target_id]["banned"] = False
            save_data()
            bot.answer_callback_query(call.id, "✅ Unbanned. Approve to restore access.")
            return
        if data == "admin_pending":
            pending_list = [u_id for u_id, u_info in users.items() if not u_info.get("approved") and not u_info.get("rejected") and not u_info.get("banned")]
            markup = InlineKeyboardMarkup()
            for u_id in pending_list[:20]:
                markup.row(
                    InlineKeyboardButton(f"✅ Approve {u_id}", callback_data=f"approve_{u_id}"),
                    InlineKeyboardButton(f"❌ Reject {u_id}", callback_data=f"reject_{u_id}"),
                )
            markup.row(InlineKeyboardButton("⬅ Back", callback_data="admin_home"))
            bot.edit_message_text(
                f"⏳ <b>PENDING APPROVAL USERS ({len(pending_list)}):</b>",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=markup,
                parse_mode="HTML",
            )
            return
        if data == "admin_running":
            lines = ["🟢 <b>ACTIVE RUNNING SCRIPTS:</b>\n"]
            count = 0
            with state_lock:
                items = [(u, f) for (u, f), rec in active_scripts.items() if rec.get("proc") and rec["proc"].poll() is None]
            for u, f in items:
                count += 1
                lines.append(f"• User <code>{u}</code>: <code>{safe_html(f)}</code>")
            if count == 0:
                lines.append("No scripts currently running.")
            markup = InlineKeyboardMarkup()
            markup.row(InlineKeyboardButton("⬅ Back", callback_data="admin_home"))
            bot.edit_message_text(
                "\n".join(lines),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=markup,
                parse_mode="HTML",
            )
            return
        if data == "admin_stop_all":
            with state_lock:
                keys = list(active_scripts.keys())
            for u, f in keys:
                stop_user_script(u, f)
            bot.answer_callback_query(call.id, "🛑 All scripts across the server stopped!")
            bot.edit_message_text(
                get_admin_panel_text(),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=admin_panel_markup(),
                parse_mode="HTML",
            )
            return
        if data == "admin_broadcast":
            admin_states[uid] = "broadcast"
            bot.answer_callback_query(call.id)
            bot.send_message(uid, "📢 <b>Send the message you want to broadcast to all users</b> (or send /cancel):", parse_mode="HTML")
            return
        if data == "admin_pip":
            admin_states[uid] = "pip_install"
            bot.answer_callback_query(call.id)
            bot.send_message(
                uid,
                "📦 <b>Send the package name to install via pip</b> (e.g. <code>pyTelegramBotAPI</code>) or /cancel:",
                parse_mode="HTML",
            )
            return
        bot.answer_callback_query(call.id, "❌ Unknown admin action.")
        return

    if not is_approved(uid):
        bot.answer_callback_query(call.id, "🔐 Owner approval required.")
        return

    if data == "myfiles":
        _send_file_list(call.message.chat.id, uid, edit=(call.message.chat.id, call.message.message_id))
        return

    kind = None
    token = None
    for prefix in ("file_", "run_", "stop_", "logs_", "del_", "re_"):
        if data.startswith(prefix):
            kind = prefix[:-1]
            token = data[len(prefix):]
            break
    if not kind:
        bot.answer_callback_query(call.id, "❌ Unknown action.")
        return
    fname = resolve_token(uid, token)
    if not fname or not safe_user_file(uid, fname):
        bot.answer_callback_query(call.id, "❌ File not found.")
        return

    if kind == "file":
        user_name = call.from_user.first_name or "User"
        with state_lock:
            rec = active_scripts.get((uid, fname))
            running = bool(rec and rec.get("proc") and rec["proc"].poll() is None)
        auto = "on" if users[uid].get("restart", {}).get(fname) else "off"
        meta = log_meta.get((uid, fname), {})
        exit_bit = "" if "exit" not in meta else f"\nExit: <code>{meta.get('exit')}</code>"
        msg = (
            f"{pe(PE_STAR, '⚡')} <b>𝐀𝐜𝐭𝐢𝐨𝐧𝐬 𝐟𝐨𝐫</b>\n"
            f"<code>{safe_html(fname)}</code>\n\n"
            f"{pe(PE_PHONE, '🆔')} <b>𝐔𝐬ᴇʀ ID:</b> <code>{uid}</code>\n"
            f"{pe(PE_USER, '👤')} <b>𝐍ᴀᴍᴇ:</b> <code>{safe_html(user_name)}</code>\n"
            f"{pe(PE_CHECK, '🟢')} <b>𝐑ᴜɴɴɪɴɢ:</b> <code>{'Yes (1)' if running else 'No (0)'}</code>"
            f"{exit_bit}\n"
            f"👑 <b>DK HOSTING</b>"
        )
        tok = file_token(uid, fname)
        buttons = [
            [
                InlineKeyboardButton("▶ Run", callback_data=f"run_{tok}"),
                InlineKeyboardButton("⏹ Stop", callback_data=f"stop_{tok}"),
            ],
            [
                InlineKeyboardButton("📜 Logs", callback_data=f"logs_{tok}"),
                InlineKeyboardButton("🗑 Delete", callback_data=f"del_{tok}"),
            ],
            [InlineKeyboardButton(f"🔁 Auto-restart: {auto}", callback_data=f"re_{tok}")],
            [InlineKeyboardButton("⬅ Back", callback_data="myfiles")],
        ]
        bot.edit_message_text(
            msg,
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=InlineKeyboardMarkup(buttons),
            parse_mode="HTML",
        )
        return

    if kind == "run":
        status = start_script(uid, fname)
        if status == "already":
            bot.answer_callback_query(call.id, "Already running.")
            return
        if status == "busy":
            bot.answer_callback_query(call.id, "Concurrent limit reached.")
            return
        if status != "started":
            bot.answer_callback_query(call.id, "❌ Could not start.")
            return
        bot.answer_callback_query(call.id, f"▶ {fname} started!")
        notify_owner(f"<b>Script Started</b>\nUser: <code>{uid}</code>\nFile: <code>{safe_html(fname)}</code>", 2)
        return

    if kind == "stop":
        if stop_user_script(uid, fname):
            bot.answer_callback_query(call.id, f"⏹ {fname} stopped!")
            notify_owner(f"<b>Script Stopped</b>\nUser: <code>{uid}</code>\nFile: <code>{safe_html(fname)}</code>", 3)
        else:
            bot.answer_callback_query(call.id, "❌ Script is not running.")
        return

    if kind == "logs":
        key = (uid, fname)
        with state_lock:
            file_logs = list(logs_store.get(key, []))
        meta = log_meta.get(key, {})
        log_text = "\n".join(file_logs[-25:]) if file_logs else "No output logs recorded yet."
        if "exit" in meta:
            log_text += f"\n[exit] {meta.get('exit')} {meta.get('note', '')}"
        tok = file_token(uid, fname)
        markup = InlineKeyboardMarkup()
        markup.row(
            InlineKeyboardButton("🔄 Refresh Logs", callback_data=f"logs_{tok}"),
            InlineKeyboardButton("⬅ Back", callback_data=f"file_{tok}"),
        )
        try:
            bot.edit_message_text(
                f"📜 <b>Logs for <code>{safe_html(fname)}</code>:</b>\n\n<pre>{safe_html(log_text[-3500:])}</pre>",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=markup,
                parse_mode="HTML",
            )
        except Exception as e:
            log_error("logs edit", e)
            bot.answer_callback_query(call.id, "Logs unchanged.")
        return

    if kind == "del":
        stop_user_script(uid, fname)
        path = safe_user_file(uid, fname)
        if path and os.path.isfile(path) and not os.path.islink(path):
            try:
                os.remove(path)
            except Exception as e:
                log_error("delete file", e)
        if fname in users[uid]["files"]:
            users[uid]["files"].remove(fname)
            save_data()
        with state_lock:
            logs_store.pop((uid, fname), None)
            log_meta.pop((uid, fname), None)
        bot.answer_callback_query(call.id, f"🗑 {fname} deleted!")
        _send_file_list(call.message.chat.id, uid, edit=(call.message.chat.id, call.message.message_id))
        return

    if kind == "re":
        current = bool(users[uid].get("restart", {}).get(fname))
        users[uid].setdefault("restart", {})[fname] = not current
        save_data()
        bot.answer_callback_query(call.id, "Auto-restart " + ("on" if not current else "off"))
        return


# ============================================================
# RESTORE
# ============================================================

def restore_all():
    load_data()
    print("🔄 Restoring scripts...")
    for uid, data in list(users.items()):
        if data.get("banned"):
            continue
        if not is_owner(uid) and not data.get("approved", False):
            continue
        folder = user_folder(uid)
        if ISOLATION_MODE == "setuid" and SANDBOX_UID > 0:
            try:
                os.chown(folder, SANDBOX_UID, SANDBOX_GID or SANDBOX_UID)
                os.chmod(folder, 0o700)
            except OSError as e:
                log_error("chown sandbox", e)
        for fname in data.get("files", []):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(folder, fname)
            if os.path.isfile(path) and not os.path.islink(path):
                status = start_script(uid, path and fname)
                if status == "busy":
                    _log.info("restore skipped %s/%s: concurrent limit", uid, fname)
                    break
                time.sleep(1)
    print("✅ System Ready")
    print(f"ISOLATION: {ISOLATION_MODE} — {ISOLATION_NOTE}")


if __name__ == "__main__":
    print("==================================================")
    print("🔧 DK HOSTING BOT | CREDIT: DK")
    print("==================================================")
    ISOLATION_MODE, ISOLATION_NOTE = detect_isolation()
    print(f"ISOLATION: {ISOLATION_MODE}")
    print(ISOLATION_NOTE)
    server_thread = threading.Thread(target=run_web_server, daemon=True)
    server_thread.start()
    print("✅ Web Server started for Render Port Binding")
    threading.Thread(target=watchdog_loop, daemon=True).start()
    restore_all()
    try:
        bot.remove_webhook()
        time.sleep(1)
    except Exception as e:
        log_error("Webhook removal warning", e)
    try:
        notify_owner(
            f"<b>DK HOSTING started</b>\nIsolation: <code>{safe_html(ISOLATION_MODE)}</code>\n{safe_html(ISOLATION_NOTE)}",
            0,
        )
    except Exception as e:
        log_error("startup notify", e)
    print("DK HOSTING BOT IS RUNNING 🏃")
    while True:
        try:
            bot.infinity_polling(skip_pending=True, timeout=60, long_polling_timeout=60)
        except Exception as e:
            log_error("polling crashed", e)
            time.sleep(5)
