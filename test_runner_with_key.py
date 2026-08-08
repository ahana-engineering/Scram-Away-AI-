"""
Run the full test suite, passing your Gemini API key directly on the
command line -- no .env file, no PowerShell session variable, nothing
that can get lost between terminal windows.

Usage:
    py test_runner_with_key.py AIzaSy...your_real_key_here...

If you omit the key, it still runs using Tier 1 + Tier 2 only (Tier 3
will be skipped), so you can also just run:
    py test_runner_with_key.py
"""

import sys
import os

if len(sys.argv) > 1:
    os.environ["GEMINI_API_KEY"] = sys.argv[1]
    print(f"Using API key passed on command line (length: {len(sys.argv[1])})\n")
else:
    print("No API key passed -- Tier 3 will be skipped for this run.\n")

from detection_engine import scan_message

TEST_CASES = [
    ("P1", "Dear customer, ur A/C will be BLOCKED today. Update KYC now: kyc-verify.example.in/upd Call 1800XXX", "VK-KYCUPD", "High"),
    ("P2", "Congrats! You won Rs.25,000 in KBC lucky draw. Claim now: kbc-winner.example.win/claim", "AX-KBCWIN", "High"),
    ("P3", "Your SBI a/c debited Rs.42,300. Not you? Block card now: sbi-secure.example.net/block", "JX-SBIALT", "High"),
    ("L1", "Your OTP for login is 738291. Valid for 10 min. Do not share with anyone. -HDFC Bank", "VM-HDFCBK", "Low"),
    ("L2", "Rs.1200 debited from A/c XX4471 on 07-AUG-26 for Amazon purchase. Avl Bal: Rs.18,540", "VM-SBIBNK", "Low"),
    ("Z1", "RWA Notice: Society maintenance now via UPI. Pay Rs.3500 before 10th to avoid fine: rwa.example.link/pay", "+919812345610", "High"),
]

LEVEL_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def run():
    print(f"{'ID':<5}{'Score':<8}{'Level':<10}{'Tier3 ran':<12}{'Expected':<10}{'Result':<8}")
    print("-" * 60)
    passed = 0

    for case_id, content, sender, expected in TEST_CASES:
        result = scan_message(content, sender, "English")

        if expected == "High":
            ok = LEVEL_RANK[result.warning_level] >= LEVEL_RANK["High"]
        else:
            ok = LEVEL_RANK[result.warning_level] <= LEVEL_RANK["Medium"]

        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1

        tier3_ran = "Yes" if result.executed_tiers.get("tier3") else "No"
        print(f"{case_id:<5}{result.final_risk_score:<8}{result.warning_level:<10}{tier3_ran:<12}{expected:<10}{status:<8}")

    print("-" * 60)
    print(f"{passed}/{len(TEST_CASES)} passed")


if __name__ == "__main__":
    run()
