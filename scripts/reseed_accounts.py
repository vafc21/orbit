#!/usr/bin/env python3
import argparse
import json
import random
from datetime import datetime, date, timedelta, timezone
from pathlib import Path

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri"]
BASE_DUE_DATE = date(2026, 2, 16)

CLASS_TEMPLATE = [
    {"id": "alg-2", "name": "Algebra II", "room": "B214", "teacher": "Ms. Patel", "color": "#2de2a6"},
    {"id": "bio", "name": "Biology", "room": "C110", "teacher": "Mr. Rivera", "color": "#4ac8ff"},
    {"id": "us-history", "name": "US History", "room": "D301", "teacher": "Dr. Chen", "color": "#ffb347"},
    {"id": "english", "name": "English 10", "room": "A102", "teacher": "Mrs. Quinn", "color": "#ff7a63"},
    {"id": "ap-cs", "name": "AP Computer Science", "room": "Lab 3", "teacher": "Mr. Ortiz", "color": "#6bdcff"},
]

PERIODS = [
    ("07:50", "08:35"),
    ("08:40", "09:25"),
    ("09:30", "10:15"),
    ("10:20", "11:05"),
    ("11:10", "11:55"),
]

BLOCK_PERIODS = [
    ("08:00", "09:20"),
    ("09:30", "10:50"),
    ("11:10", "12:30"),
    ("13:10", "14:30"),
]

TODO_TEMPLATES = [
    ("Finish algebra practice set", 0, "Show all work and check corrections."),
    ("Quizlet prep: Biology key terms", 1, "Review 20 terms in Learn mode."),
    ("US History DBQ outline", 3, "Draft thesis and three evidence bullets."),
    ("AP CS quiz correction", 5, "Fix missed questions and note patterns."),
]

STUDY_SET_TEMPLATES = [
    {
        "title": "Quizlet Prep: Biology Essentials",
        "description": "Core cell and genetics terms for this week's quiz.",
        "visibility": "private",
        "cards": [
            ("Mitosis", "Cell division producing two identical daughter cells."),
            ("ATP", "Primary molecule cells use to store and transfer energy."),
            ("Osmosis", "Movement of water across a semipermeable membrane."),
            ("Ribosome", "Cell structure that builds proteins."),
        ],
    },
    {
        "title": "Quizlet Prep: US History Review",
        "description": "Terms and concepts for the unit assessment.",
        "visibility": "public",
        "cards": [
            ("Federalism", "Division of power between national and state governments."),
            ("New Deal", "Relief and reform programs during the Great Depression."),
            ("Cold War", "Long geopolitical rivalry between the US and USSR."),
            ("Civil Rights Act", "Law that outlawed discrimination in public life."),
        ],
    },
]


def slugify(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-")
    return cleaned or "user"


def build_classes():
    return [dict(item) for item in CLASS_TEMPLATE]


def username_seed(username_slug: str) -> int:
    return sum(ord(ch) for ch in username_slug)


def parse_time_to_minutes(value: str) -> int:
    hours, minutes = value.split(":")
    return int(hours) * 60 + int(minutes)


def minutes_to_time(value: int) -> str:
    value = value % (24 * 60)
    hours = value // 60
    minutes = value % 60
    return f"{hours:02d}:{minutes:02d}"


def shift_time(value: str, minutes: int) -> str:
    return minutes_to_time(parse_time_to_minutes(value) + minutes)


def rotate_list(items, steps: int):
    if not items:
        return []
    steps = steps % len(items)
    return items[steps:] + items[:steps]


def build_daily_schedule(username_slug: str, classes):
    seed = username_seed(username_slug)
    base_class_ids = [item["id"] for item in classes]
    if not base_class_ids:
        return {day: [] for day in DAYS}
    shift_options = [-12, -8, -4, 0, 6, 10]
    user_shift = shift_options[seed % len(shift_options)]
    class_ids = rotate_list(base_class_ids, seed)
    if seed % 2 == 1:
        class_ids = list(reversed(class_ids))
    room_by_id = {item["id"]: item.get("room", "") for item in classes}
    schedule = {day: [] for day in DAYS}
    day_entries = []
    for index, ((start, end), class_id) in enumerate(zip(PERIODS, class_ids), start=1):
        day_entries.append(
            {
                "classId": class_id,
                "start": shift_time(start, user_shift),
                "end": shift_time(end, user_shift),
                "location": room_by_id.get(class_id, ""),
                "slot": index,
            }
        )
    for day in DAYS:
        entries = []
        for entry in day_entries:
            entries.append(
                {
                    "id": f"seed-{username_slug}-{day.lower()}-{entry['slot']}",
                    "classId": entry["classId"],
                    "start": entry["start"],
                    "end": entry["end"],
                    "location": entry["location"],
                }
            )
        schedule[day] = entries
    return schedule


def build_ab_schedule(username_slug: str, classes):
    seed = username_seed(username_slug)
    base_class_ids = [item["id"] for item in classes]
    if not base_class_ids:
        return {day: [] for day in DAYS}
    shift_options = [-10, -6, -2, 0, 4, 8]
    user_shift = shift_options[seed % len(shift_options)]
    room_by_id = {item["id"]: item.get("room", "") for item in classes}

    a_ids = rotate_list(base_class_ids, seed + 1)
    b_ids = rotate_list(base_class_ids, seed + 3)
    if seed % 2 == 0:
        b_ids = list(reversed(b_ids))

    def build_template(class_ids, offset):
        template = []
        for index, ((start, end), class_id) in enumerate(zip(PERIODS, class_ids), start=1):
            template.append(
                {
                    "slot": index,
                    "classId": class_id,
                    "start": shift_time(start, user_shift + offset),
                    "end": shift_time(end, user_shift + offset),
                    "location": room_by_id.get(class_id, ""),
                }
            )
        return template

    a_template = build_template(a_ids, -2)
    b_template = build_template(b_ids, 2)
    day_template = {"Mon": a_template, "Tue": b_template, "Wed": a_template, "Thu": b_template, "Fri": a_template}
    schedule = {day: [] for day in DAYS}
    for day in DAYS:
        schedule[day] = [
            {
                "id": f"seed-{username_slug}-{day.lower()}-{entry['slot']}",
                "classId": entry["classId"],
                "start": entry["start"],
                "end": entry["end"],
                "location": entry["location"],
            }
            for entry in day_template[day]
        ]
    return schedule


def build_block_schedule(username_slug: str, classes):
    seed = username_seed(username_slug)
    base_class_ids = [item["id"] for item in classes]
    if not base_class_ids:
        return {day: [] for day in DAYS}
    room_by_id = {item["id"]: item.get("room", "") for item in classes}
    shift_options = [-6, -3, 0, 3, 6]
    base_shift = shift_options[seed % len(shift_options)]
    schedule = {day: [] for day in DAYS}

    for day_index, day in enumerate(DAYS):
        class_ids = rotate_list(base_class_ids, seed + day_index + 1)
        if (seed + day_index) % 2 == 1:
            class_ids = list(reversed(class_ids))
        day_shift = base_shift + day_index
        entries = []
        for index, ((start, end), class_id) in enumerate(zip(BLOCK_PERIODS, class_ids), start=1):
            entries.append(
                {
                    "id": f"seed-{username_slug}-{day.lower()}-{index}",
                    "classId": class_id,
                    "start": shift_time(start, day_shift),
                    "end": shift_time(end, day_shift),
                    "location": room_by_id.get(class_id, ""),
                }
            )
        schedule[day] = entries
    return schedule


def build_schedule(username_slug: str, classes, schedule_profile: str):
    profile = str(schedule_profile or "").strip().lower()
    if profile == "daily":
        return build_daily_schedule(username_slug, classes)
    if profile == "ab":
        return build_ab_schedule(username_slug, classes)
    return build_block_schedule(username_slug, classes)


def build_todos(username_slug: str, classes):
    class_ids = [item["id"] for item in classes]
    todos = []
    for index, (title, offset, notes) in enumerate(TODO_TEMPLATES, start=1):
        due_date = (BASE_DUE_DATE + timedelta(days=offset)).strftime("%Y-%m-%d")
        todos.append(
            {
                "id": f"seed-todo-{username_slug}-{index}",
                "classId": class_ids[(index - 1) % len(class_ids)],
                "title": title,
                "dueDate": due_date,
                "notes": notes,
                "completed": False,
            }
        )
    return todos


def build_study(username_slug: str):
    sets = []
    cards = []
    progress = {}
    created_at = "2026-02-14T00:00:00Z"
    for set_index, set_template in enumerate(STUDY_SET_TEMPLATES, start=1):
        set_id = f"seed-set-{username_slug}-{set_index}"
        sets.append(
            {
                "id": set_id,
                "title": set_template["title"],
                "description": set_template["description"],
                "createdAt": created_at,
                "visibility": set_template["visibility"],
            }
        )
        for card_index, (term, definition) in enumerate(set_template["cards"], start=1):
            card_id = f"seed-card-{username_slug}-{set_index}-{card_index}"
            cards.append(
                {
                    "id": card_id,
                    "setId": set_id,
                    "term": term,
                    "definition": definition,
                    "starred": False,
                }
            )
            progress[card_id] = {
                "cardId": card_id,
                "seenCount": 0,
                "correctCount": 0,
                "wrongCount": 0,
                "mastery": 0,
            }
    return {
        "sets": sets,
        "cards": cards,
        "progress": progress,
        "activeSet": sets[0]["id"] if sets else None,
    }


def reseed_accounts(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    users = payload.get("users")
    if not isinstance(users, dict):
        raise ValueError("orbit-data.json is missing a users object")

    covered_users = sorted([username for username in users.keys() if username != "Vlad"], key=lambda item: item.lower())
    schedule_types = ["daily", "ab", "block"]
    rng = random.SystemRandom()
    randomized_users = covered_users[:]
    rng.shuffle(randomized_users)
    randomized_types = []
    for schedule_type in schedule_types:
        if len(randomized_types) < len(randomized_users):
            randomized_types.append(schedule_type)
    while len(randomized_types) < len(randomized_users):
        randomized_types.append(rng.choice(schedule_types))
    rng.shuffle(randomized_types)
    schedule_profile_by_user = {
        username: randomized_types[index] for index, username in enumerate(randomized_users)
    }

    for username, entry in users.items():
        if not isinstance(entry, dict):
            entry = {}
            users[username] = entry
        if username == "Vlad":
            continue
        username_slug = slugify(username)
        classes = build_classes()
        schedule_profile = schedule_profile_by_user.get(username, "block")
        entry["classes"] = classes
        entry["schedule"] = build_schedule(username_slug, classes, schedule_profile)
        entry["scheduleProfile"] = schedule_profile
        entry["todos"] = build_todos(username_slug, classes)
        entry["study"] = build_study(username_slug)

    payload["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Reseed Orbit account classes/schedule/todos/study data")
    parser.add_argument(
        "--data-file",
        default="orbit-data.json",
        help="Path to orbit-data.json (default: orbit-data.json)",
    )
    args = parser.parse_args()
    reseed_accounts(Path(args.data_file))


if __name__ == "__main__":
    main()
