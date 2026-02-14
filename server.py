#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote

APP_DIR = Path(__file__).resolve().parent
INDEX_FILE = APP_DIR / "index.html"
SIGNIN_FILE = APP_DIR / "signin.html"
LANDING_FILE = APP_DIR / "landing.html"
ABOUT_FILE = APP_DIR / "about.html"
USER_PAGE_FILE = APP_DIR / "user.html"
DATA_FILE = APP_DIR / "orbit-data.json"
USER_FILE = APP_DIR / "orbit-user.json"
CHAT_DIR = APP_DIR / "orbit-chats"
ASSET_DIR = APP_DIR / "assets"
CHAT_KEY_FILE = APP_DIR / "orbit-chat.key"

SESSION_COOKIE = "orbit_session"
SESSIONS = {}

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri"]
MAX_BODY_BYTES = 5 * 1024 * 1024
DEMO_PASSWORD = "orbitdemo"
DEMO_USERNAMES = ["jordan", "avery", "riley"]
CHAT_RETENTION_DAYS = 30
MAX_AVATAR_CHARS = 1_500_000
CHAT_KEY_CACHE = None


def is_demo_allowed():
    value = os.environ.get("ORBIT_ALLOW_DEMO", "")
    return value.lower() in ("1", "true", "yes", "on")


def normalize_username(value):
    return str(value or "").strip()


def resolve_username(name, users=None):
    name = normalize_username(name)
    if not name:
        return None
    if users is None:
        users = load_users().get("users", {})
    if name in users:
        return name
    lowered = name.lower()
    for username in users.keys():
        if username.lower() == lowered:
            return username
    return None


def chat_encryption_key():
    global CHAT_KEY_CACHE
    if CHAT_KEY_CACHE:
        return CHAT_KEY_CACHE
    value = os.environ.get("ORBIT_CHAT_KEY", "").strip()
    if value:
        CHAT_KEY_CACHE = value
        return CHAT_KEY_CACHE
    try:
        if CHAT_KEY_FILE.exists():
            value = CHAT_KEY_FILE.read_text(encoding="utf-8").strip()
            if value:
                CHAT_KEY_CACHE = value
                return CHAT_KEY_CACHE
    except Exception:
        pass
    value = secrets.token_urlsafe(32)
    CHAT_KEY_CACHE = value
    try:
        CHAT_KEY_FILE.write_text(value, encoding="utf-8")
        try:
            os.chmod(CHAT_KEY_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass
    return CHAT_KEY_CACHE


def ensure_chat_dir():
    CHAT_DIR.mkdir(parents=True, exist_ok=True)


def safe_username(username):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", username)


def chat_store_path(username):
    ensure_chat_dir()
    return CHAT_DIR / f"{safe_username(username)}.json"


def xor_bytes(data, key_bytes):
    return bytes(byte ^ key_bytes[index % len(key_bytes)] for index, byte in enumerate(data))


def load_chat_store(username):
    path = chat_store_path(username)
    if not path.exists():
        return {"threads": {}}, None
    record = load_json(path)
    if not isinstance(record, dict):
        return {"threads": {}}, None
    payload = record.get("payload")
    if record.get("encrypted"):
        key = chat_encryption_key()
        if not key:
            return {"threads": {}}, "locked"
        try:
            key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
            raw = base64.b64decode(payload or "")
            decoded = xor_bytes(raw, key_bytes)
            data = json.loads(decoded.decode("utf-8"))
        except Exception:
            return {"threads": {}}, None
    else:
        if isinstance(payload, str):
            try:
                data = json.loads(payload)
            except Exception:
                data = {}
        elif isinstance(payload, dict):
            data = payload
        else:
            data = record
    if not isinstance(data, dict):
        return {"threads": {}}, None
    threads = data.get("threads")
    if isinstance(threads, dict):
        return {"threads": threads}, None
    return {"threads": {}}, None


def save_chat_store(username, threads):
    path = chat_store_path(username)
    data = {"threads": threads}
    raw = json.dumps(data).encode("utf-8")
    key = chat_encryption_key()
    if key:
        key_bytes = hashlib.sha256(key.encode("utf-8")).digest()
        encrypted = xor_bytes(raw, key_bytes)
        record = {"encrypted": True, "payload": base64.b64encode(encrypted).decode("ascii")}
    else:
        record = {"encrypted": False, "payload": raw.decode("utf-8")}
    write_json(path, record)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def parse_message_timestamp(value):
    if not value:
        return None
    try:
        cleaned = str(value).replace("Z", "")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None


def prune_chat_threads(threads):
    cutoff = datetime.utcnow() - timedelta(days=CHAT_RETENTION_DAYS)
    changed = False
    for class_id, thread in list(threads.items()):
        if not isinstance(thread, list):
            threads[class_id] = []
            changed = True
            continue
        filtered = []
        for message in thread:
            if not isinstance(message, dict):
                changed = True
                continue
            timestamp = parse_message_timestamp(message.get("created_at"))
            if timestamp and timestamp < cutoff:
                changed = True
                continue
            filtered.append(message)
        if len(filtered) != len(thread):
            changed = True
        threads[class_id] = filtered
    return changed


def dm_thread_id(user_a, user_b):
    pair = sorted([user_a, user_b], key=lambda item: item.lower())
    return f"dm:{pair[0]}:{pair[1]}"


def group_thread_id(group_id):
    return f"group:{group_id}"


def guess_content_type(path):
    suffix = path.suffix.lower()
    if suffix == ".png":
        return "image/png"
    if suffix in (".jpg", ".jpeg"):
        return "image/jpeg"
    if suffix == ".svg":
        return "image/svg+xml"
    if suffix == ".webp":
        return "image/webp"
    return "application/octet-stream"


def default_data():
    return {
        "classes": [],
        "schedule": {day: [] for day in DAYS},
    }


def demo_data_template(username):
    base_classes = [
        {"id": "math", "name": "Algebra II", "room": "B214", "teacher": "Ms. Patel", "color": "#4ac8ff"},
        {"id": "bio", "name": "Biology", "room": "C110", "teacher": "Mr. Rivera", "color": "#2de2a6"},
        {"id": "hist", "name": "World History", "room": "D301", "teacher": "Dr. Chen", "color": "#ffb347"},
        {"id": "eng", "name": "English Lit", "room": "A102", "teacher": "Mrs. Quinn", "color": "#ff6b6b"},
    ]
    if username == "avery":
        base_classes.append(
            {"id": "cs", "name": "AP Computer Science", "room": "Lab 3", "teacher": "Mr. Ortiz", "color": "#9b7bff"}
        )
    if username == "riley":
        base_classes.append(
            {"id": "chem", "name": "Chemistry", "room": "Lab 2", "teacher": "Ms. Liu", "color": "#ffd166"}
        )
    schedule = {day: [] for day in DAYS}
    schedule["Mon"] = [
        {"id": "event-1", "classId": "math", "start": "08:10", "end": "09:00", "location": "B214"},
        {"id": "event-2", "classId": "bio", "start": "09:10", "end": "10:00", "location": "C110"},
        {"id": "event-3", "classId": "hist", "start": "10:15", "end": "11:05", "location": "D301"},
    ]
    schedule["Tue"] = [
        {"id": "event-4", "classId": "eng", "start": "08:10", "end": "09:00", "location": "A102"},
        {"id": "event-5", "classId": "math", "start": "09:10", "end": "10:00", "location": "B214"},
    ]
    schedule["Wed"] = [
        {"id": "event-6", "classId": "bio", "start": "08:10", "end": "09:00", "location": "C110"},
        {"id": "event-7", "classId": "hist", "start": "09:10", "end": "10:00", "location": "D301"},
    ]
    schedule["Thu"] = [
        {"id": "event-8", "classId": "eng", "start": "08:10", "end": "09:00", "location": "A102"},
        {"id": "event-9", "classId": "math", "start": "09:10", "end": "10:00", "location": "B214"},
    ]
    schedule["Fri"] = [
        {"id": "event-10", "classId": "bio", "start": "08:10", "end": "09:00", "location": "C110"},
        {"id": "event-11", "classId": "hist", "start": "09:10", "end": "10:00", "location": "D301"},
    ]
    if username == "avery":
        schedule["Wed"].append(
            {"id": "event-12", "classId": "cs", "start": "10:15", "end": "11:05", "location": "Lab 3"}
        )
    if username == "riley":
        schedule["Tue"].append(
            {"id": "event-13", "classId": "chem", "start": "10:15", "end": "11:05", "location": "Lab 2"}
        )
    return {"classes": base_classes, "schedule": schedule}


def is_demo_user(user):
    return bool(user and user.get("demo"))


def load_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_json(path, payload):
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_users():
    data = load_json(USER_FILE)
    payload = {"users": {}}
    if isinstance(data, dict):
        if isinstance(data.get("users"), dict):
            payload = data
        elif data.get("username") and data.get("password_hash") and data.get("salt"):
            payload["users"][data["username"]] = {
                "username": data.get("username"),
                "salt": data.get("salt"),
                "password_hash": data.get("password_hash"),
                "created_at": data.get("created_at"),
                "demo": False,
            }
    if ensure_demo_users(payload):
        payload["updated_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        write_json(USER_FILE, payload)
    return payload


def ensure_demo_users(payload):
    users = payload.setdefault("users", {})
    changed = False
    for username in DEMO_USERNAMES:
        if username in users:
            if users[username].get("demo") is not True:
                users[username]["demo"] = True
                changed = True
            continue
        users[username] = create_user(username, DEMO_PASSWORD, demo=True)
        changed = True
    return changed


def save_users(payload):
    payload["updated_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    write_json(USER_FILE, payload)


def get_user_record(username):
    users_payload = load_users()
    users = users_payload.get("users", {})
    return users.get(username)


def user_configured():
    users_payload = load_users()
    users = users_payload.get("users", {})
    return any(user for user in users.values() if user and not user.get("demo"))


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 160_000)


def create_user(username, password, demo=False):
    salt = secrets.token_bytes(16)
    pw_hash = hash_password(password, salt)
    return {
        "username": username,
        "salt": base64.b64encode(salt).decode("ascii"),
        "password_hash": base64.b64encode(pw_hash).decode("ascii"),
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "demo": demo,
    }


def register_account(username, password):
    if not username or len(password) < 6:
        return HTTPStatus.BAD_REQUEST, {"error": "username and 6+ char password required"}
    users_payload = load_users()
    users = users_payload.get("users", {})
    existing = resolve_username(username, users)
    if existing:
        return HTTPStatus.BAD_REQUEST, {"error": "username already exists"}
    user = create_user(username, password, demo=False)
    users_payload.setdefault("users", {})[username] = user
    save_users(users_payload)
    store, changed = ensure_user_data(username)
    if changed:
        save_data_store(store)
    return HTTPStatus.OK, {"username": username}


def verify_user(username, password):
    user = get_user_record(username)
    if not user:
        return False
    try:
        salt = base64.b64decode(user.get("salt", ""))
        stored_hash = base64.b64decode(user.get("password_hash", ""))
    except Exception:
        return False
    computed = hash_password(password, salt)
    return secrets.compare_digest(stored_hash, computed)


def load_data_store():
    data = load_json(DATA_FILE)
    if not isinstance(data, dict):
        return {"users": {}}
    if isinstance(data.get("users"), dict):
        return data
    if "classes" in data or "schedule" in data:
        return {"users": {"__legacy__": sanitize_data(data)}, "updated_at": data.get("updated_at")}
    return {"users": {}}


def save_data_store(store):
    store["updated_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    write_json(DATA_FILE, store)


def ensure_demo_data(store):
    users_payload = load_users()
    users = users_payload.get("users", {})
    data_users = store.setdefault("users", {})
    changed = False
    for username, user in users.items():
        if not is_demo_user(user):
            continue
        template = sanitize_data(demo_data_template(username))
        entry = data_users.get(username)
        if not isinstance(entry, dict):
            data_users[username] = template
            changed = True
            continue
        classes = entry.get("classes")
        if not isinstance(classes, list) or not classes:
            entry["classes"] = template["classes"]
            changed = True
        schedule = entry.get("schedule")
        schedule_empty = True
        if isinstance(schedule, dict):
            schedule_empty = all(not isinstance(schedule.get(day), list) or not schedule.get(day) for day in DAYS)
        if schedule_empty:
            entry["schedule"] = template["schedule"]
            changed = True
    return changed


def ensure_user_data(username):
    store = load_data_store()
    users = store.setdefault("users", {})
    if username in users:
        return store, False
    if "__legacy__" in users:
        users[username] = users.pop("__legacy__")
        return store, True
    users[username] = default_data()
    return store, True


def get_user_entry(username):
    store = load_data_store()
    changed = False
    if ensure_demo_data(store):
        changed = True
    users = store.setdefault("users", {})
    if username not in users:
        if "__legacy__" in users:
            users[username] = users.pop("__legacy__")
        else:
            users[username] = default_data()
        changed = True
    return store, users[username], changed


def get_user_chats(username):
    store, entry, changed = get_user_entry(username)
    chat_store, error = load_chat_store(username)
    threads = chat_store.get("threads", {})
    if isinstance(entry.get("chats"), dict):
        for class_id, messages in entry["chats"].items():
            if not isinstance(messages, list):
                continue
            threads.setdefault(class_id, []).extend(messages)
        entry.pop("chats", None)
        changed = True
    if prune_chat_threads(threads):
        save_chat_store(username, threads)
    if changed:
        save_data_store(store)
    return store, threads, error


def append_message_to_users(usernames, thread_id, message):
    for username in usernames:
        store, chats, error = get_user_chats(username)
        if error == "locked":
            return "locked"
        thread = chats.get(thread_id)
        if not isinstance(thread, list):
            thread = []
            chats[thread_id] = thread
        thread.append(message)
        prune_chat_threads(chats)
        save_chat_store(username, chats)
    return None


def get_user_friends(username):
    store, entry, changed = get_user_entry(username)
    friends = entry.get("friends")
    if not isinstance(friends, list):
        friends = []
        entry["friends"] = friends
        changed = True
    return store, friends, changed


def get_user_settings(username):
    store, entry, changed = get_user_entry(username)
    settings = entry.get("settings")
    if not isinstance(settings, dict):
        settings = {}
        entry["settings"] = settings
        changed = True
    return store, settings, changed


def save_user_settings(username, settings):
    store, entry, changed = get_user_entry(username)
    entry["settings"] = settings if isinstance(settings, dict) else {}
    save_data_store(store)


def get_user_groups(username):
    store, entry, changed = get_user_entry(username)
    groups = entry.get("groups")
    if not isinstance(groups, list):
        groups = []
        entry["groups"] = groups
        changed = True
    return store, groups, changed


def sanitize_profile(profile):
    if not isinstance(profile, dict):
        return {"bio": "", "avatar": ""}
    bio = str(profile.get("bio") or "").strip()
    avatar = str(profile.get("avatar") or "").strip()
    if len(avatar) > MAX_AVATAR_CHARS:
        avatar = ""
    return {"bio": bio, "avatar": avatar}


def get_user_profile(username):
    store, entry, changed = get_user_entry(username)
    profile = entry.get("profile")
    if not isinstance(profile, dict):
        profile = {"bio": "", "avatar": ""}
        entry["profile"] = profile
        changed = True
    cleaned = sanitize_profile(profile)
    if cleaned != profile:
        entry["profile"] = cleaned
        changed = True
    return store, cleaned, changed


def save_user_profile(username, profile):
    store, entry, changed = get_user_entry(username)
    entry["profile"] = sanitize_profile(profile)
    save_data_store(store)


def ensure_store_user_entry(store, username):
    users = store.setdefault("users", {})
    if username not in users:
        if "__legacy__" in users:
            users[username] = users.pop("__legacy__")
        else:
            users[username] = default_data()
    entry = users.get(username)
    if not isinstance(entry, dict):
        entry = default_data()
        users[username] = entry
    return entry


def ensure_request_data(entry):
    requests = entry.get("friend_requests")
    changed = False
    if not isinstance(requests, dict):
        requests = {"incoming": [], "outgoing": []}
        entry["friend_requests"] = requests
        changed = True
    incoming = requests.get("incoming")
    if not isinstance(incoming, list):
        incoming = []
        requests["incoming"] = incoming
        changed = True
    outgoing = requests.get("outgoing")
    if not isinstance(outgoing, list):
        outgoing = []
        requests["outgoing"] = outgoing
        changed = True
    return incoming, outgoing, changed


def get_user_requests(username):
    store, entry, changed = get_user_entry(username)
    incoming, outgoing, updated = ensure_request_data(entry)
    return store, incoming, outgoing, changed or updated


def add_friend_entry(entry, other_username):
    friends = entry.get("friends")
    if not isinstance(friends, list):
        friends = []
        entry["friends"] = friends
    existing = get_friend_usernames(friends)
    if other_username.lower() in existing:
        return None
    friend = {
        "id": f"friend-{secrets.token_hex(4)}",
        "name": other_username,
        "username": other_username,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    friends.append(friend)
    return friend


def pop_request_by_id(requests, request_id):
    if not request_id:
        return None
    for index, item in enumerate(requests):
        if isinstance(item, dict) and item.get("id") == request_id:
            return requests.pop(index)
    return None


def pop_request_by_user(requests, username, key):
    if not username:
        return None
    for index, item in enumerate(requests):
        if not isinstance(item, dict):
            continue
        value = normalize_username(item.get(key))
        if value and value.lower() == username.lower():
            return requests.pop(index)
    return None


def send_friend_request(user, target_name):
    users_payload = load_users()
    users = users_payload.get("users", {})
    target_user = resolve_username(target_name, users)
    if not target_user:
        return HTTPStatus.BAD_REQUEST, {"error": "user not found"}
    if target_user == user:
        return HTTPStatus.BAD_REQUEST, {"error": "cannot add yourself"}
    store = load_data_store()
    ensure_demo_data(store)
    entry_user = ensure_store_user_entry(store, user)
    entry_target = ensure_store_user_entry(store, target_user)
    friends = entry_user.get("friends", [])
    if target_user.lower() in get_friend_usernames(friends):
        return HTTPStatus.BAD_REQUEST, {"error": "friend already added"}
    incoming_user, outgoing_user, _ = ensure_request_data(entry_user)
    incoming_target, outgoing_target, _ = ensure_request_data(entry_target)
    if any(
        isinstance(req, dict) and normalize_username(req.get("to")).lower() == target_user.lower()
        for req in outgoing_user
    ):
        return HTTPStatus.BAD_REQUEST, {"error": "request already sent"}
    if any(
        isinstance(req, dict) and normalize_username(req.get("from")).lower() == target_user.lower()
        for req in incoming_user
    ):
        return HTTPStatus.BAD_REQUEST, {"error": "request already received"}
    if any(
        isinstance(req, dict) and normalize_username(req.get("from")).lower() == user.lower()
        for req in incoming_target
    ):
        return HTTPStatus.BAD_REQUEST, {"error": "request already pending"}
    request = {
        "id": f"req-{secrets.token_hex(4)}",
        "from": user,
        "to": target_user,
        "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    outgoing_user.append(request)
    incoming_target.append(request)
    save_data_store(store)
    return HTTPStatus.OK, {"request": request}


def get_friend_usernames(friends):
    usernames = set()
    for friend in friends:
        if not isinstance(friend, dict):
            continue
        value = friend.get("username") or friend.get("name") or ""
        value = normalize_username(value)
        if value:
            usernames.add(value.lower())
    return usernames


def user_is_friend(viewer, target):
    if not viewer or not target:
        return False
    if viewer.lower() == target.lower():
        return True
    store, friends, changed = get_user_friends(viewer)
    if changed:
        save_data_store(store)
    friend_names = get_friend_usernames(friends)
    return target.lower() in friend_names


def parse_member_list(value):
    if isinstance(value, list):
        raw = value
    elif isinstance(value, str):
        raw = value.split(",")
    else:
        raw = []
    members = []
    for entry in raw:
        name = normalize_username(entry)
        if name:
            members.append(name)
    return members


def add_group_to_user(store, username, group):
    users = store.setdefault("users", {})
    entry = users.get(username)
    if not isinstance(entry, dict):
        entry = default_data()
        users[username] = entry
    groups = entry.get("groups")
    if not isinstance(groups, list):
        groups = []
        entry["groups"] = groups
    if not any(isinstance(item, dict) and item.get("id") == group.get("id") for item in groups):
        groups.append(group)


def load_user_data(username):
    store = load_data_store()
    if ensure_demo_data(store):
        save_data_store(store)
    users = store.get("users", {})
    if username in users:
        return users[username]
    if "__legacy__" in users:
        return users["__legacy__"]
    return default_data()


def sanitize_data(data):
    if not isinstance(data, dict):
        return default_data()

    classes_in = data.get("classes") if isinstance(data.get("classes"), list) else []
    clean_classes = []
    class_ids = set()

    for entry in classes_in:
        if not isinstance(entry, dict):
            continue
        class_id = str(entry.get("id") or "").strip()
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        if not class_id:
            class_id = f"class-{secrets.token_hex(4)}"
        if class_id in class_ids:
            continue
        class_ids.add(class_id)
        clean_classes.append(
            {
                "id": class_id,
                "name": name,
                "room": str(entry.get("room") or "").strip(),
                "teacher": str(entry.get("teacher") or "").strip(),
                "color": str(entry.get("color") or "#4ac8ff").strip(),
            }
        )

    schedule_in = data.get("schedule") if isinstance(data.get("schedule"), dict) else {}
    clean_schedule = {day: [] for day in DAYS}

    for day in DAYS:
        entries = schedule_in.get(day, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            class_id = str(entry.get("classId") or "").strip()
            if class_id not in class_ids:
                continue
            item_id = str(entry.get("id") or "").strip()
            if not item_id:
                item_id = f"event-{secrets.token_hex(4)}"
            clean_schedule[day].append(
                {
                    "id": item_id,
                    "classId": class_id,
                    "start": str(entry.get("start") or "").strip(),
                    "end": str(entry.get("end") or "").strip(),
                    "location": str(entry.get("location") or "").strip(),
                }
            )

    return {
        "classes": clean_classes,
        "schedule": clean_schedule,
    }


def save_user_data(username, data):
    store = load_data_store()
    if ensure_demo_data(store):
        pass
    users = store.setdefault("users", {})
    users.pop("__legacy__", None)
    existing = users.get(username, {})
    base = sanitize_data(data)
    if isinstance(existing, dict):
        if isinstance(existing.get("friends"), list):
            base["friends"] = existing["friends"]
        if isinstance(existing.get("settings"), dict):
            base["settings"] = existing["settings"]
        if isinstance(existing.get("groups"), list):
            base["groups"] = existing["groups"]
        if isinstance(existing.get("friend_requests"), dict):
            base["friend_requests"] = existing["friend_requests"]
        if isinstance(existing.get("profile"), dict):
            base["profile"] = existing["profile"]
    users[username] = base
    save_data_store(store)


def parse_cookies(cookie_header):
    cookies = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.strip().split("=", 1)
        cookies[name] = value
    return cookies


def get_session_user(headers):
    cookies = parse_cookies(headers.get("Cookie", ""))
    session_id = cookies.get(SESSION_COOKIE)
    if session_id and session_id in SESSIONS:
        return SESSIONS[session_id]
    return None


def set_session(headers, username):
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = username
    headers.append(
        (
            "Set-Cookie",
            f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Strict",
        )
    )


def clear_session(headers, session_id):
    if session_id:
        SESSIONS.pop(session_id, None)
    headers.append(
        (
            "Set-Cookie",
            f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
        )
    )


class OrbitHandler(BaseHTTPRequestHandler):
    server_version = "OrbitServer/1.0"

    def _send_response(self, status, headers=None, body=b""):
        self.send_response(status)
        if headers:
            for name, value in headers:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, payload, status=HTTPStatus.OK, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        self._send_response(status, headers, body)

    def _send_html(self, path):
        if not path.exists():
            self._send_json({"error": "missing file"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        body = path.read_bytes()
        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
        ]
        self._send_response(HTTPStatus.OK, headers, body)

    def _format_time(self, timestamp):
        return timestamp.strftime("%I:%M %p").lstrip("0")

    def _redirect(self, location):
        headers = [("Location", location), ("Cache-Control", "no-store")]
        self._send_response(HTTPStatus.FOUND, headers)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY_BYTES:
            self._send_json({"error": "payload too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return None
        body = self.rfile.read(length) if length else b""
        if not body:
            return {}
        try:
            return json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "invalid json"}, status=HTTPStatus.BAD_REQUEST)
            return None

    def _require_auth(self):
        user = get_session_user(self.headers)
        if not user:
            self._send_json({"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
            return None
        return user

    def do_GET(self):
        path = urlparse(self.path).path

        if path.startswith("/assets/"):
            asset_rel = path[len("/assets/") :]
            asset_path = (ASSET_DIR / asset_rel).resolve()
            try:
                asset_path.relative_to(ASSET_DIR)
            except ValueError:
                self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            if not asset_path.is_file():
                self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            body = asset_path.read_bytes()
            headers = [
                ("Content-Type", f"{guess_content_type(asset_path)}"),
                ("Cache-Control", "no-store"),
            ]
            self._send_response(HTTPStatus.OK, headers, body)
            return

        if path in ("/", "/index.html"):
            if not get_session_user(self.headers):
                self._send_html(LANDING_FILE)
            else:
                self._send_html(INDEX_FILE)
            return

        if path in ("/landing", "/landing.html"):
            self._send_html(LANDING_FILE)
            return

        if path in ("/about", "/about.html"):
            self._send_html(ABOUT_FILE)
            return

        if path.startswith("/u/"):
            if not get_session_user(self.headers):
                self._redirect("/signin")
                return
            self._send_html(USER_PAGE_FILE)
            return

        if path in ("/signin", "/signin.html"):
            if get_session_user(self.headers):
                self._redirect("/")
                return
            self._send_html(SIGNIN_FILE)
            return

        if path == "/api/status":
            self._send_json({"configured": user_configured()})
            return

        if path == "/api/me":
            user = self._require_auth()
            if not user:
                return
            self._send_json({"username": user})
            return

        if path == "/api/profile":
            user = self._require_auth()
            if not user:
                return
            store, profile, changed = get_user_profile(user)
            if changed:
                save_data_store(store)
            self._send_json({"username": user, "profile": profile})
            return

        if path.startswith("/api/profile/"):
            user = self._require_auth()
            if not user:
                return
            target_raw = unquote(path[len("/api/profile/") :]).strip("/")
            if not target_raw:
                self._send_json({"error": "user required"}, status=HTTPStatus.BAD_REQUEST)
                return
            users_payload = load_users()
            users = users_payload.get("users", {})
            target_user = resolve_username(target_raw, users)
            if not target_user:
                self._send_json({"error": "user not found"}, status=HTTPStatus.NOT_FOUND)
                return
            store, profile, changed = get_user_profile(target_user)
            if changed:
                save_data_store(store)
            data = load_user_data(target_user)
            can_view_schedule = user_is_friend(user, target_user)
            if not can_view_schedule:
                data = {"classes": [], "schedule": {day: [] for day in DAYS}}
            self._send_json(
                {
                    "username": target_user,
                    "profile": profile,
                    "classes": data.get("classes", []),
                    "schedule": data.get("schedule", {}),
                    "shared": can_view_schedule,
                }
            )
            return

        if path == "/api/data":
            user = self._require_auth()
            if not user:
                return
            self._send_json(load_user_data(user))
            return

        if path == "/api/chats":
            user = self._require_auth()
            if not user:
                return
            store, chats, error = get_user_chats(user)
            if error == "locked":
                self._send_json({"error": "chat storage locked"}, status=HTTPStatus.LOCKED)
                return
            self._send_json({"chats": chats})
            return

        if path == "/api/friends":
            user = self._require_auth()
            if not user:
                return
            store, friends, changed = get_user_friends(user)
            users_payload = load_users()
            users = users_payload.get("users", {})
            updated = False
            for friend in friends:
                if not isinstance(friend, dict):
                    continue
                if not friend.get("username") and friend.get("name"):
                    resolved = resolve_username(friend.get("name"), users)
                    if resolved:
                        friend["username"] = resolved
                        updated = True
            if changed or updated:
                save_data_store(store)
            self._send_json({"friends": friends})
            return

        if path == "/api/friend-requests":
            user = self._require_auth()
            if not user:
                return
            store, incoming, outgoing, changed = get_user_requests(user)
            if changed:
                save_data_store(store)
            self._send_json({"incoming": incoming, "outgoing": outgoing})
            return

        if path == "/api/groups":
            user = self._require_auth()
            if not user:
                return
            store, groups, changed = get_user_groups(user)
            if changed:
                save_data_store(store)
            self._send_json({"groups": groups})
            return

        if path == "/api/settings":
            user = self._require_auth()
            if not user:
                return
            store, settings, changed = get_user_settings(user)
            if changed:
                save_data_store(store)
            self._send_json({"settings": settings})
            return

        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/setup":
            payload = self._read_json()
            if payload is None:
                return
            username = str(payload.get("username") or "").strip()
            password = str(payload.get("password") or "")
            status, response = register_account(username, password)
            if status != HTTPStatus.OK:
                self._send_json(response, status=status)
                return
            headers = []
            set_session(headers, username)
            self._send_json({}, extra_headers=headers)
            return

        if path == "/api/signup":
            payload = self._read_json()
            if payload is None:
                return
            username = str(payload.get("username") or "").strip()
            password = str(payload.get("password") or "")
            status, response = register_account(username, password)
            if status != HTTPStatus.OK:
                self._send_json(response, status=status)
                return
            headers = []
            set_session(headers, username)
            self._send_json({}, extra_headers=headers)
            return

        if path == "/api/login":
            payload = self._read_json()
            if payload is None:
                return
            username = str(payload.get("username") or "").strip()
            password = str(payload.get("password") or "")
            user = get_user_record(username)
            if user and is_demo_user(user) and not is_demo_allowed():
                self._send_json({"error": "demo access disabled"}, status=HTTPStatus.UNAUTHORIZED)
                return
            if not user:
                if not user_configured():
                    self._send_json({"error": "not configured"}, status=HTTPStatus.BAD_REQUEST)
                    return
                self._send_json({"error": "invalid credentials"}, status=HTTPStatus.UNAUTHORIZED)
                return
            if not verify_user(username, password):
                self._send_json({"error": "invalid credentials"}, status=HTTPStatus.UNAUTHORIZED)
                return
            headers = []
            set_session(headers, username)
            self._send_json({}, extra_headers=headers)
            return

        if path == "/api/logout":
            cookies = parse_cookies(self.headers.get("Cookie", ""))
            session_id = cookies.get(SESSION_COOKIE)
            headers = []
            clear_session(headers, session_id)
            self._send_json({}, extra_headers=headers)
            return

        if path == "/api/data":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            save_user_data(user, payload)
            self._send_json({"ok": True})
            return

        if path == "/api/chats":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            text = str(payload.get("text") or "").strip()
            if not text:
                self._send_json({"error": "text required"}, status=HTTPStatus.BAD_REQUEST)
                return
            class_id = str(payload.get("classId") or "").strip()
            target_name = normalize_username(payload.get("to"))
            group_id = str(payload.get("groupId") or "").strip()
            recipients = []
            thread_id = None

            if class_id:
                recipients = [user]
                thread_id = class_id
            elif target_name:
                users_payload = load_users()
                users = users_payload.get("users", {})
                target_user = resolve_username(target_name, users)
                if not target_user:
                    self._send_json({"error": "user not found"}, status=HTTPStatus.BAD_REQUEST)
                    return
                if target_user == user:
                    self._send_json({"error": "cannot message yourself"}, status=HTTPStatus.BAD_REQUEST)
                    return
                store, friends, changed = get_user_friends(user)
                if changed:
                    save_data_store(store)
                friend_names = get_friend_usernames(friends)
                if target_user.lower() not in friend_names:
                    self._send_json({"error": "friend not added"}, status=HTTPStatus.BAD_REQUEST)
                    return
                recipients = [user, target_user]
                thread_id = dm_thread_id(user, target_user)
            elif group_id:
                store, groups, changed = get_user_groups(user)
                if changed:
                    save_data_store(store)
                group = next((item for item in groups if isinstance(item, dict) and item.get("id") == group_id), None)
                if not group:
                    self._send_json({"error": "group not found"}, status=HTTPStatus.NOT_FOUND)
                    return
                raw_members = group.get("members")
                if not isinstance(raw_members, list) or not raw_members:
                    self._send_json({"error": "group members missing"}, status=HTTPStatus.BAD_REQUEST)
                    return
                members = [normalize_username(member) for member in raw_members if normalize_username(member)]
                if not members:
                    self._send_json({"error": "group members missing"}, status=HTTPStatus.BAD_REQUEST)
                    return
                members_lower = {member.lower() for member in members}
                if user.lower() not in members_lower:
                    self._send_json({"error": "not a group member"}, status=HTTPStatus.FORBIDDEN)
                    return
                recipients = []
                seen = set()
                for member in members:
                    key = member.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    recipients.append(member)
                thread_id = group_thread_id(group_id)
            else:
                self._send_json(
                    {"error": "classId, to, or groupId required"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return

            now = datetime.utcnow()
            message = {
                "id": f"msg-{secrets.token_hex(4)}",
                "sender": user,
                "text": text,
                "time": self._format_time(now),
                "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            error = append_message_to_users(recipients, thread_id, message)
            if error == "locked":
                self._send_json({"error": "chat storage locked"}, status=HTTPStatus.LOCKED)
                return
            self._send_json({"message": message, "threadId": thread_id})
            return

        if path == "/api/friends":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            name = normalize_username(payload.get("name"))
            if not name:
                self._send_json({"error": "name required"}, status=HTTPStatus.BAD_REQUEST)
                return
            status, response = send_friend_request(user, name)
            self._send_json(response, status=status)
            return

        if path == "/api/friend-requests":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            name = normalize_username(payload.get("name") or payload.get("to"))
            if not name:
                self._send_json({"error": "name required"}, status=HTTPStatus.BAD_REQUEST)
                return
            status, response = send_friend_request(user, name)
            self._send_json(response, status=status)
            return

        if path == "/api/friend-requests/accept":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            request_id = str(payload.get("id") or "").strip()
            from_name = normalize_username(payload.get("from"))
            if not request_id and not from_name:
                self._send_json({"error": "id or from required"}, status=HTTPStatus.BAD_REQUEST)
                return
            users_payload = load_users()
            users = users_payload.get("users", {})
            store = load_data_store()
            ensure_demo_data(store)
            entry_user = ensure_store_user_entry(store, user)
            incoming, outgoing, _ = ensure_request_data(entry_user)
            req = pop_request_by_id(incoming, request_id) or pop_request_by_user(incoming, from_name, "from")
            if not req:
                self._send_json({"error": "request not found"}, status=HTTPStatus.NOT_FOUND)
                return
            sender = resolve_username(req.get("from"), users) or normalize_username(req.get("from"))
            if not sender:
                self._send_json({"error": "request sender missing"}, status=HTTPStatus.BAD_REQUEST)
                return
            entry_sender = ensure_store_user_entry(store, sender)
            incoming_sender, outgoing_sender, _ = ensure_request_data(entry_sender)
            pop_request_by_id(outgoing_sender, req.get("id")) or pop_request_by_user(outgoing_sender, user, "to")
            friend = add_friend_entry(entry_user, sender)
            add_friend_entry(entry_sender, user)
            save_data_store(store)
            self._send_json({"friend": friend or {"name": sender, "username": sender}})
            return

        if path == "/api/friend-requests/decline":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            request_id = str(payload.get("id") or "").strip()
            from_name = normalize_username(payload.get("from"))
            if not request_id and not from_name:
                self._send_json({"error": "id or from required"}, status=HTTPStatus.BAD_REQUEST)
                return
            users_payload = load_users()
            users = users_payload.get("users", {})
            store = load_data_store()
            ensure_demo_data(store)
            entry_user = ensure_store_user_entry(store, user)
            incoming, outgoing, _ = ensure_request_data(entry_user)
            req = pop_request_by_id(incoming, request_id) or pop_request_by_user(incoming, from_name, "from")
            if not req:
                self._send_json({"error": "request not found"}, status=HTTPStatus.NOT_FOUND)
                return
            sender = resolve_username(req.get("from"), users) or normalize_username(req.get("from"))
            if sender:
                entry_sender = ensure_store_user_entry(store, sender)
                incoming_sender, outgoing_sender, _ = ensure_request_data(entry_sender)
                pop_request_by_id(outgoing_sender, req.get("id")) or pop_request_by_user(outgoing_sender, user, "to")
            save_data_store(store)
            self._send_json({"ok": True})
            return

        if path == "/api/friend-requests/cancel":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            request_id = str(payload.get("id") or "").strip()
            to_name = normalize_username(payload.get("to"))
            if not request_id and not to_name:
                self._send_json({"error": "id or to required"}, status=HTTPStatus.BAD_REQUEST)
                return
            users_payload = load_users()
            users = users_payload.get("users", {})
            store = load_data_store()
            ensure_demo_data(store)
            entry_user = ensure_store_user_entry(store, user)
            incoming, outgoing, _ = ensure_request_data(entry_user)
            req = pop_request_by_id(outgoing, request_id) or pop_request_by_user(outgoing, to_name, "to")
            if not req:
                self._send_json({"error": "request not found"}, status=HTTPStatus.NOT_FOUND)
                return
            target = resolve_username(req.get("to"), users) or normalize_username(req.get("to"))
            if target:
                entry_target = ensure_store_user_entry(store, target)
                incoming_target, outgoing_target, _ = ensure_request_data(entry_target)
                pop_request_by_id(incoming_target, req.get("id")) or pop_request_by_user(incoming_target, user, "from")
            save_data_store(store)
            self._send_json({"ok": True})
            return

        if path == "/api/friends/remove":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            friend_id = str(payload.get("id") or "").strip()
            if not friend_id:
                self._send_json({"error": "id required"}, status=HTTPStatus.BAD_REQUEST)
                return
            store, friends, changed = get_user_friends(user)
            updated = [item for item in friends if not (isinstance(item, dict) and item.get("id") == friend_id)]
            if len(updated) == len(friends):
                self._send_json({"error": "friend not found"}, status=HTTPStatus.NOT_FOUND)
                return
            store["users"][user]["friends"] = updated
            save_data_store(store)
            self._send_json({"ok": True})
            return

        if path == "/api/groups":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            name = str(payload.get("name") or "").strip()
            if not name:
                self._send_json({"error": "name required"}, status=HTTPStatus.BAD_REQUEST)
                return
            members_input = parse_member_list(payload.get("members"))
            users_payload = load_users()
            users = users_payload.get("users", {})
            members = []
            missing = []
            seen = set()
            for entry in members_input + [user]:
                resolved = resolve_username(entry, users)
                if not resolved:
                    missing.append(entry)
                    continue
                key = resolved.lower()
                if key in seen:
                    continue
                seen.add(key)
                members.append(resolved)
            if missing:
                self._send_json(
                    {"error": "unknown members", "missing": missing},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            if len(members) < 2:
                self._send_json(
                    {"error": "add at least one other member"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            group = {
                "id": f"group-{secrets.token_hex(4)}",
                "name": name,
                "members": members,
                "created_by": user,
                "created_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            store = load_data_store()
            if ensure_demo_data(store):
                pass
            for member in members:
                add_group_to_user(store, member, group)
            save_data_store(store)
            self._send_json({"group": group})
            return

        if path == "/api/profile":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            profile_input = payload.get("profile") if isinstance(payload, dict) else None
            if profile_input is None:
                profile_input = payload
            if not isinstance(profile_input, dict):
                self._send_json({"error": "profile required"}, status=HTTPStatus.BAD_REQUEST)
                return
            avatar_raw = str(profile_input.get("avatar") or "")
            if len(avatar_raw) > MAX_AVATAR_CHARS:
                self._send_json({"error": "avatar too large"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            save_user_profile(user, profile_input)
            self._send_json({"ok": True})
            return

        if path == "/api/settings":
            user = self._require_auth()
            if not user:
                return
            payload = self._read_json()
            if payload is None:
                return
            settings = payload.get("settings")
            if settings is None:
                self._send_json({"error": "settings required"}, status=HTTPStatus.BAD_REQUEST)
                return
            save_user_settings(user, settings)
            self._send_json({"ok": True})
            return

        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)


def main():
    parser = argparse.ArgumentParser(description="Orbit local server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), OrbitHandler)
    print(f"Orbit server running on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == "__main__":
    main()
