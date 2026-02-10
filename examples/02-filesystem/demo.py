#!/usr/bin/env python3
"""
Filesystem Sandbox Demo

This script demonstrates greywall's filesystem controls:
- allowWrite: Only specific directories are writable
- denyWrite: Block writes to sensitive files
- denyRead: Block reads from sensitive paths

Run WITHOUT greywall to see all operations succeed.
Run WITH greywall to see unauthorized operations blocked.
"""

import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
os.chdir(SCRIPT_DIR)

results = []


def log(operation, status, message):
    icon = "✓" if status == "success" else "✗"
    print(f"[{icon}] {operation}: {message}")
    results.append({"operation": operation, "status": status, "message": message})


def try_write(filepath, content, description):
    """Attempt to write to a file."""
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        log(description, "success", f"Wrote to {filepath}")
        return True
    except PermissionError:
        log(description, "blocked", f"Permission denied: {filepath}")
        return False
    except OSError as e:
        log(description, "blocked", f"OS error: {e}")
        return False


def try_read(filepath, description):
    """Attempt to read from a file."""
    try:
        path = Path(filepath)
        content = path.read_text()
        log(description, "success", f"Read {len(content)} bytes from {filepath}")
        return True
    except PermissionError:
        log(description, "blocked", f"Permission denied: {filepath}")
        return False
    except FileNotFoundError:
        log(description, "skipped", f"File not found: {filepath}")
        return False
    except OSError as e:
        log(description, "blocked", f"OS error: {e}")
        return False


def cleanup():
    """Clean up test files."""
    import shutil

    try:
        shutil.rmtree(SCRIPT_DIR / "output", ignore_errors=True)
        (SCRIPT_DIR / "unauthorized.txt").unlink(missing_ok=True)
        (SCRIPT_DIR / ".env").unlink(missing_ok=True)
        (SCRIPT_DIR / "secrets.key").unlink(missing_ok=True)
    except Exception:
        pass


def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║  Filesystem Sandbox Demo                                  ║
╠═══════════════════════════════════════════════════════════╣
║  Tests greywall's filesystem controls:                       ║
║    - allowWrite: Only ./output/ is writable               ║
║    - denyWrite: .env and *.key files are protected        ║
║    - denyRead: /etc/shadow is blocked                     ║
╚═══════════════════════════════════════════════════════════╝
""")

    cleanup()

    print("--- WRITE TESTS ---\n")

    # Test 1: Write to allowed directory (should succeed)
    try_write(
        "output/data.txt",
        "This file is in the allowed output directory.\n",
        "Write to ./output/ (allowed)",
    )

    # Test 2: Write to project root (should fail with greywall)
    try_write(
        "unauthorized.txt",
        "This should not be writable.\n",
        "Write to ./ (not in allowWrite)",
    )

    # Test 3: Write to .env file (should fail - denyWrite)
    try_write(".env", "SECRET_KEY=stolen\n", "Write to .env (in denyWrite)")

    # Test 4: Write to .key file (should fail - denyWrite pattern)
    try_write(
        "secrets.key", "-----BEGIN PRIVATE KEY-----\n", "Write to *.key (in denyWrite)"
    )

    print("\n--- READ TESTS ---\n")

    # Test 5: Read from allowed file (should succeed)
    try_read("demo.py", "Read ./demo.py (allowed)")

    # Test 6: Read from /etc/shadow (should fail - denyRead)
    try_read("/etc/shadow", "Read /etc/shadow (in denyRead)")

    # Test 7: Read from /etc/passwd (should fail if in denyRead)
    try_read("/etc/passwd", "Read /etc/passwd (in denyRead)")

    # Summary
    print("\n--- SUMMARY ---\n")

    blocked = sum(1 for r in results if r["status"] == "blocked")
    succeeded = sum(1 for r in results if r["status"] == "success")
    skipped = sum(1 for r in results if r["status"] == "skipped")

    if skipped > 0:
        print(f"({skipped} test(s) skipped - file not found)")

    if blocked > 0:
        print(f"✅ Greywall blocked {blocked} unauthorized operation(s)")
        print(f"{succeeded} allowed operation(s) succeeded")
        print("\nFilesystem sandbox is working!\n")
    else:
        print("⚠️ All operations succeeded - you are likely not running in greywall")
        print("Run with: greywall --settings greywall.json python demo.py\n")

    cleanup()


if __name__ == "__main__":
    main()
