#!/usr/bin/env python3
"""
Password Optimizer
------------------
Evaluates a user-provided password and optionally strengthens it by
adding missing character types (uppercase, lowercase, digits, symbols)
or extending it to a desired target length.

Author: Your Name
GitHub: https://github.com/yourusername
"""

import string
import secrets
import sys
from typing import Dict

_sysrand = secrets.SystemRandom()  # For secure shuffling


def evaluate_password(pw: str) -> Dict[str, object]:
    """
    Evaluate which character categories the password contains.
    Returns a dictionary describing the password’s composition.
    """
    has_lower = any(c in string.ascii_lowercase for c in pw)
    has_upper = any(c in string.ascii_uppercase for c in pw)
    has_digit = any(c in string.digits for c in pw)
    has_symbol = any(c in string.punctuation for c in pw)

    missing = 4 - sum([has_lower, has_upper, has_digit, has_symbol])

    return {
        "length": len(pw),
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "missing_count": missing,
    }


def strengthen_password(
    pw: str,
    add_lower: bool,
    add_upper: bool,
    add_digit: bool,
    add_symbol: bool,
    target_length: int | None = None,
) -> str:
    """
    Return a strengthened password by adding missing types and filling up
    to the desired target length. Uses cryptographically secure randomness.
    """
    pools = {
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digit": string.digits,
        "symbol": string.punctuation,
    }

    chosen_pools = []
    if add_lower:
        chosen_pools.append("lower")
    if add_upper:
        chosen_pools.append("upper")
    if add_digit:
        chosen_pools.append("digit")
    if add_symbol:
        chosen_pools.append("symbol")

    if not chosen_pools and (not target_length or target_length <= len(pw)):
        return pw  # nothing to add

    new_chars = []

    # Ensure at least one of each selected type
    if add_lower:
        new_chars.append(secrets.choice(pools["lower"]))
    if add_upper:
        new_chars.append(secrets.choice(pools["upper"]))
    if add_digit:
        new_chars.append(secrets.choice(pools["digit"]))
    if add_symbol:
        new_chars.append(secrets.choice(pools["symbol"]))

    # Combine allowed characters
    allowed_pool = "".join(pools[p] for p in chosen_pools) or (
        string.ascii_letters + string.digits + string.punctuation
    )

    # Determine final target length
    final_target = (
        max(len(pw) + len(new_chars), len(pw))
        if target_length is None
        else max(target_length, len(pw) + len(new_chars))
    )

    # Fill remaining spots
    remaining = final_target - (len(pw) + len(new_chars))
    for _ in range(remaining):
        new_chars.append(secrets.choice(allowed_pool))

    # Shuffle and join
    combined = list(pw) + new_chars
    _sysrand.shuffle(combined)
    return "".join(combined)


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question and return True for yes."""
    default_str = "y" if default else "n"
    resp = input(f"{prompt} (y/n, default {default_str}): ").strip().lower()
    if not resp:
        return default
    return resp.startswith("y")


def main():
    print("=" * 60)
    print("🔐  PASSWORD OPTIMIZER")
    print("=" * 60)

    password = input("Enter your current password: ").strip()
    if not password:
        print("Password cannot be empty. Exiting.")
        sys.exit(1)

    info = evaluate_password(password)
    print("\nPassword analysis:")
    print(f" - Length: {info['length']}")
    print(f" - Contains lowercase: {'Yes' if info['has_lower'] else 'No'}")
    print(f" - Contains uppercase: {'Yes' if info['has_upper'] else 'No'}")
    print(f" - Contains digits:   {'Yes' if info['has_digit'] else 'No'}")
    print(f" - Contains symbols:  {'Yes' if info['has_symbol'] else 'No'}")
    print(f" - Missing categories: {info['missing_count']}")

    if info["missing_count"] == 0:
        print("\n✅ Your password already contains all character types!")
        if not ask_yes_no("Would you like to make it longer anyway?", False):
            print("All good! Stay safe. 🔒")
            return
        try:
            target_len = int(input("Enter desired length (e.g., 16): ").strip())
        except Exception:
            print("Invalid input. Exiting.")
            return
        strengthened = strengthen_password(password, False, False, False, False, target_len)
        print("\n🔁 Strengthened password:")
        print(strengthened)
        return

    print("\nWhich missing types would you like to add?")
    add_lower = False if info["has_lower"] else ask_yes_no("Add lowercase letters?", True)
    add_upper = False if info["has_upper"] else ask_yes_no("Add uppercase letters?", True)
    add_digit = False if info["has_digit"] else ask_yes_no("Add digits?", True)
    add_symbol = False if info["has_symbol"] else ask_yes_no("Add symbols?", True)

    if not any([add_lower, add_upper, add_digit, add_symbol]):
        print("No changes selected. Exiting.")
        return

    default_target = max(info["length"] + sum([add_lower, add_upper, add_digit, add_symbol]), 12)
    try:
        t_input = input(f"Enter target length (default {default_target}): ").strip()
        target_len = int(t_input) if t_input else default_target
        if target_len < info["length"]:
            print("Target length cannot be shorter than the current password.")
            return
    except Exception:
        print("Invalid number. Exiting.")
        return

    strengthened = strengthen_password(
        password,
        add_lower=add_lower,
        add_upper=add_upper,
        add_digit=add_digit,
        add_symbol=add_symbol,
        target_length=target_len,
    )

    print("\n✅ Strengthened password:")
    print(strengthened)
    print("\nNotes:")
    print(" - Added characters were placed randomly for better security.")
    print(" - You can safely publish this code on GitHub.")
    print("=" * 60)


if __name__ == "__main__":
    main()
