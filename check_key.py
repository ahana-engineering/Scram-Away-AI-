"""
RUN THIS FILE: py check_key.py

This is the ONE file to use -- delete debug_tier3.py, debug_tier3_v2.py,
and debug_tier3_v3.py if you still have them, so there's no confusion
about which one you're running.

Setup required before running (one time only):
1. A file named EXACTLY ".env" must exist in this same folder.
2. It must contain exactly one line, no quotes, no spaces around "=":
   GEMINI_API_KEY=AIzaSy...your real key...
"""

import os
import sys
import glob

print("=" * 50)
print("STEP 1: Checking files in this folder")
print("=" * 50)
all_files = os.listdir(".")
print(all_files)

if not os.path.exists(".env"):
    print("\n*** No .env file found in this folder at all. ***")
    print("*** Create one with Notepad, save as 'All Files', named exactly '.env' ***")
    sys.exit(1)
print("\nFound .env file. Reading it now...")

print("\n" + "=" * 50)
print("STEP 2: Loading the .env file")
print("=" * 50)
try:
    from dotenv import load_dotenv
except ImportError:
    print("python-dotenv not installed. Run: py -m pip install python-dotenv")
    sys.exit(1)

load_dotenv()
api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("*** .env was loaded but GEMINI_API_KEY was not found inside it. ***")
    print("*** Check the file contains exactly: GEMINI_API_KEY=yourkey (no quotes/spaces) ***")
    sys.exit(1)

print(f"Key found. Length: {len(api_key)}")
print(f"Key starts with: {api_key[:6]}...")

if len(api_key) < 30 or "your" in api_key.lower() or "here" in api_key.lower() or " " in api_key:
    print("\n*** This does NOT look like a real Gemini key. ***")
    print("*** Real keys start with 'AIza' and are about 39 characters, no spaces, no words. ***")
    sys.exit(1)

print("\n" + "=" * 50)
print("STEP 3: Calling Gemini directly")
print("=" * 50)
try:
    from google import genai

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents="Say hello in one word.",
    )
    print("\n*** SUCCESS ***")
    print("Gemini responded:", response.text)
except Exception as e:
    print("\n*** FAILED ***")
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {e}")
