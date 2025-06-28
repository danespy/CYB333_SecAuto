# Password Strength Analyzer 🔐

## Project Objectives
This tool helps users understand how strong their passwords are. It checks things like password length, character variety, and whether the password is easy to guess or very common. This project is part of the CYB333 security automation course.

## Features (Planned)
- Checks if the password is long enough
- Checks if it uses uppercase, lowercase, numbers, and symbols
- Warns if it's a very common or weak password
- Gives a score like "Weak", "Moderate", or "Strong"
- Can check if the password has appeared in a real data breach

## Installing Required Packages
- Before running the program, you must install required Python packages:
    - pip install -r requirements.txt
    - This will install `requests`, which is needed for the HaveIBeenPwned API check.

## Notes About blacklist.txt
- Make sure the file `blacklist.txt` is in the same directory as `main.py`. This file contains known weak passwords. If it's missing, the program will skip the blacklist check.

## How to Run the Program
1. Make sure Python is installed on your computer.
2. Open the terminal in VS Code (or Command Prompt).
3. Navigate to your project folder.

## Files in This Project
- `main.py`: The main Python script where password analysis will be done.
- `README.md`: This file you're reading now.
- `requirements.txt`: This lists any Python packages your project needs.

## Example Output

Below is an example of running the program:

⚠️ Warning: blacklist.txt not found.

Password Strength: Weak
Entropy: 15.51 bits
Feedback:
- Too short (less than 8 characters).
- No uppercase letters.
- No lowercase letters.
- Contains numbers.
- No special characters.
- Estimated entropy: 15.51 bits
- ⚠️ This password has appeared in 130075037 data breaches!


## Requirements
- Python 3.11 or higher

## Author
Created by Danilo Espy 