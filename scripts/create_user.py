"""Create a pilot user offline; passwords never appear in shell arguments or logs."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.security import hash_password, ROLES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", choices=sorted(ROLES), required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", args.username):
        parser.error("Use 1-80 ASCII username characters")
    users = json.loads(args.file.read_text(encoding="utf-8-sig")) if args.file.exists() else {}
    if args.username in users:
        parser.error("Existing user will not be overwritten; review the user file manually")
    password = getpass.getpass("Password (16+ characters): ")
    if len(password) < 16 or password != getpass.getpass("Confirm password: "):
        parser.error("Password too short or confirmation mismatch")
    users[args.username] = {"role": args.role, "password_hash": hash_password(password)}
    args.file.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.file.with_suffix(".tmp")
    with temporary.open("x", encoding="utf-8") as output:
        json.dump(users, output, indent=2)
    os.chmod(temporary, 0o600)
    temporary.replace(args.file)
    print("User saved. Restart the service to reload offline account changes.")


if __name__ == "__main__":
    main()
