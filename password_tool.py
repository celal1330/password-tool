"""
Password Generator & Validator (CLI Edition)
Just a small utility I made to mess around with password strength logic.
"""

import string, random, re, hashlib, secrets
from typing import Dict
import math

# ---------------------------------------------------------
# Password Generator Class
# ---------------------------------------------------------
class PasswordGenerator:
    # Generates strong passwords with a few knobs to tweak
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate(self, length=16, use_lower=True, use_upper=True,
                 use_digits=True, use_special=True, exclude_amb=False):
        if length < 8:
            raise ValueError("Password must be at least 8 characters long")

        chars = ""
        must_include = []

        # build character pool
        if use_lower:
            tmp = self.lowercase
            if exclude_amb:
                tmp = tmp.replace('l', '')
            chars += tmp
            must_include.append(secrets.choice(tmp))

        if use_upper:
            tmp = self.uppercase
            if exclude_amb:
                tmp = tmp.replace('O', '').replace('I', '')
            chars += tmp
            must_include.append(secrets.choice(tmp))

        if use_digits:
            tmp = self.digits
            if exclude_amb:
                tmp = tmp.replace('0', '').replace('1', '')
            chars += tmp
            must_include.append(secrets.choice(tmp))

        if use_special:
            chars += self.symbols
            must_include.append(secrets.choice(self.symbols))

        if not chars:
            raise ValueError("Please enable at least one character type!")

        # assemble the password
        pwd_list = must_include[:]
        while len(pwd_list) < length:
            pwd_list.append(secrets.choice(chars))

        random.shuffle(pwd_list)  # avoid predictable ordering
        return ''.join(pwd_list)

    def make_passphrase(self, word_count=4, separator='-'):
        """just picks a few random words"""
        words = [
            'correct', 'horse', 'battery', 'staple', 'quantum', 'wizard',
            'dragon', 'cipher', 'vault', 'secure', 'phoenix', 'guardian',
            'pulse', 'matrix', 'nebula', 'spark', 'tiger', 'summit'
        ]
        chosen = [secrets.choice(words).capitalize() for _ in range(word_count)]
        return separator.join(chosen) + separator + str(secrets.randbelow(999))


# ---------------------------------------------------------
# Password Validator Class
# ---------------------------------------------------------
class PasswordValidator:
    # Checks for common patterns and rates strength
    def __init__(self):
        self.common = {'password', '123456', 'qwerty', 'admin', 'abc123', 'letmein'}

    def validate(self, pwd: str) -> Dict:
        info = {
            "password": pwd,
            "length": len(pwd),
            "score": 0,
            "strength": "",
            "checks": {},
            "feedback": []
        }

        # basic length rules
        if len(pwd) >= 8:
            info["checks"]["length_ok"] = True
            info["score"] += 1
        else:
            info["checks"]["length_ok"] = False
            info["feedback"].append("Too short! Use 8+ chars.")

        # diversity checks
        has_lower = bool(re.search(r'[a-z]', pwd))
        has_upper = bool(re.search(r'[A-Z]', pwd))
        has_digit = bool(re.search(r'\d', pwd))
        has_symbol = bool(re.search(r'[^a-zA-Z0-9]', pwd))

        info["checks"].update({
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digit": has_digit,
            "symbol": has_symbol
        })

        if has_lower: info["score"] += 1
        else: info["feedback"].append("Add lowercase letters")
        if has_upper: info["score"] += 1
        else: info["feedback"].append("Add uppercase letters")
        if has_digit: info["score"] += 1
        else: info["feedback"].append("Add digits")
        if has_symbol: info["score"] += 1
        else: info["feedback"].append("Add special characters")

        # weak patterns
        if pwd.lower() in self.common:
            info["feedback"].append("Very common password, avoid it!")
            info["score"] -= 3
        if re.search(r'(.)\1{2,}', pwd):
            info["feedback"].append("Avoid repeated characters")
            info["score"] -= 1
        if re.search(r'(123|abc|xyz|456)', pwd.lower()):
            info["feedback"].append("Avoid sequential patterns")
            info["score"] -= 1

        # classify
        score = info["score"]
        if score <= 2:
            info["strength"] = "Very Weak"
        elif score <= 4:
            info["strength"] = "Weak"
        elif score <= 6:
            info["strength"] = "Medium"
        elif score <= 8:
            info["strength"] = "Strong"
        else:
            info["strength"] = "Very Strong"

        if info["strength"] in ("Strong", "Very Strong"):
            info["feedback"].insert(0, "Nice! This looks secure.")

        return info

    def entropy(self, pwd: str) -> float:
        pool = 0
        if re.search(r'[a-z]', pwd): pool += 26
        if re.search(r'[A-Z]', pwd): pool += 26
        if re.search(r'\d', pwd): pool += 10
        if re.search(r'[^a-zA-Z0-9]', pwd): pool += 32

        return round(len(pwd) * math.log2(pool or 1), 2)

    def hash(self, pwd: str) -> str:
        return hashlib.sha256(pwd.encode()).hexdigest()


# ---------------------------------------------------------
# CLI Stuff
# ---------------------------------------------------------
def show_menu():
    print("\n" + "=" * 60)
    print(" PASSWORD TOOLKIT ")
    print("=" * 60)
    print("1. Generate Random Password")
    print("2. Generate Passphrase")
    print("3. Validate Password")
    print("4. Calculate Entropy")
    print("5. Hash Password (SHA-256)")
    print("6. Exit")
    print("=" * 60)


def main():
    gen = PasswordGenerator()
    val = PasswordValidator()

    while True:
        show_menu()
        choice = input("\nPick an option (1-6): ").strip()

        if choice == '1':
            print("\n--- Password Generator ---")
            length = int(input("Length (default 16): ") or 16)
            excl = input("Exclude confusing chars? (y/N): ").lower() == 'y'
            try:
                pwd = gen.generate(length=length, exclude_amb=excl)
                print(f"\nGenerated: {pwd}")
                result = val.validate(pwd)
                print(f"Strength: {result['strength']}")
                print(f"Entropy: {val.entropy(pwd)} bits")
            except ValueError as e:
                print(f"Error: {e}")

        elif choice == '2':
            print("\n--- Passphrase Generator ---")
            count = int(input("Number of words (default 4): ") or 4)
            sep = input("Separator (default '-'): ") or "-"
            phrase = gen.make_passphrase(count, sep)
            print(f"\nPassphrase: {phrase}")
            print(f"Strength: {val.validate(phrase)['strength']}")

        elif choice == '3':
            pwd = input("\nEnter password: ")
            info = val.validate(pwd)
            print(f"\nLength: {info['length']}")
            print(f"Score: {info['score']}/10")
            print(f"Strength: {info['strength']}")
            print(f"Entropy: {val.entropy(pwd)} bits")

            print("\nFeedback:")
            for fb in info["feedback"]:
                print(" -", fb)

        elif choice == '4':
            pwd = input("\nEnter password: ")
            bits = val.entropy(pwd)
            print(f"Entropy: {bits} bits")
            if bits < 30: print("→ very weak, easily crackable")
            elif bits < 60: print("→ okay-ish, could be better")
            elif bits < 100: print("→ strong enough for most cases")
            else: print("→ top tier, uncrackable (probably)")

        elif choice == '5':
            pwd = input("\nEnter password to hash: ")
            print("Hashing... (yep, SHA-256)")
            print(val.hash(pwd))

        elif choice == '6':
            print("\nBye 👋 Stay safe!")
            break

        else:
            print("Invalid choice, try again.")

# quick test runner
if __name__ == "__main__":
    main()
