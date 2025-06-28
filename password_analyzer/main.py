import string
import math
import hashlib
import requests

def calculate_entropy(password):
    """
    Estimate Shannon entropy of a password.
    Higher entropy means higher unpredictability.
    """
    if not password:
        return 0

    char_freq = {}
    for char in password:
        char_freq[char] = char_freq.get(char, 0) + 1

    entropy = 0
    length = len(password)
    for freq in char_freq.values():
        p = freq / length
        entropy -= p * math.log2(p)

    return round(entropy * length, 2)

def load_blacklist(file_path="blacklist.txt"):
    """
    Load a list of blacklisted passwords from a text file.
    Each line should contain one password.
    Returns a set for fast lookup.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return set(line.strip().lower() for line in file if line.strip())
    except FileNotFoundError:
        print("⚠️ Warning: blacklist.txt not found.")
        return set()

def check_pwned_password(password):
    """
    Check if the password has been exposed in a known data breach using HaveIBeenPwned API.
    Returns the number of times it was seen in breaches.
    """
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url)
        if response.status_code != 200:
            return -1  # API error

        hashes = (line.split(":") for line in response.text.splitlines())
        for hash_suffix, count in hashes:
            if hash_suffix == suffix:
                return int(count)
        return 0  # Not found
    except Exception as e:
        print("Error checking HaveIBeenPwned API:", e)
        return -1

def analyze_password(password):
    """
    Analyze the strength of a given password based on:
    - Length
    - Use of uppercase, lowercase, digits, and special characters
    Returns a strength rating and reasons.
    """
    score = 0
    reasons = []
    blacklist = load_blacklist()

    # Check password length
    if len(password) >= 12:
        score += 2
        reasons.append("Good length (12+ characters).")
    elif len(password) >= 8:
        score += 1
        reasons.append("Decent length (8+ characters).")
    else:
        reasons.append("Too short (less than 8 characters).")

    # Check for uppercase letters
    if any(char.isupper() for char in password):
        score += 1
        reasons.append("Contains uppercase letter(s).")
    else:
        reasons.append("No uppercase letters.")

    # Check for lowercase letters
    if any(char.islower() for char in password):
        score += 1
        reasons.append("Contains lowercase letter(s).")
    else:
        reasons.append("No lowercase letters.")

    # Check for digits
    if any(char.isdigit() for char in password):
        score += 1
        reasons.append("Contains numbers.")
    else:
        reasons.append("No numbers.")

    # Check for special characters
    if any(char in string.punctuation for char in password):
        score += 1
        reasons.append("Contains special character(s).")
    else:
        reasons.append("No special characters.")

    # Calculate entropy
    entropy = calculate_entropy(password)
    reasons.append(f"Estimated entropy: {entropy} bits")

    # Blacklist check
    if password.lower() in blacklist:
        reasons.append("⚠️ This password is very common or blacklisted!")
        score = 0  # Force weak score if blacklisted

    pwned_count = check_pwned_password(password)
    if pwned_count > 0:
        reasons.append(f"⚠️ This password has appeared in {pwned_count} data breaches!")
        score = 0  # Force weak score if pwned
    elif pwned_count == 0:
        reasons.append("✅ This password was not found in known breaches.")
    else:
        reasons.append("⚠️ Could not check breaches (API error).")

    # Determine strength based on total score
    if score >= 6:
        strength = "Strong"
    elif score >= 4:
        strength = "Moderate"
    else:
        strength = "Weak"

    # Return final result
    return strength, reasons, entropy


if __name__ == "__main__":
    user_input = input("Enter a password to analyze: ")
    result, feedback, entropy = analyze_password(user_input)

    print(f"\nPassword Strength: {result}")
    print(f"Entropy: {entropy} bits")
    print("Feedback:")
    for reason in feedback:
        print(f"- {reason}")