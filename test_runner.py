"""
Quick command-line test runner. Runs a sample set of test cases through the
detection engine and prints a results table. Use this to sanity-check
scoring after any change to detection_engine.py -- no frontend, no server,
no npm needed. Just: python test_runner.py
"""

from detection_engine import scan_message

# (id, content, sender, expected_min_level)
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
    print(f"{'ID':<5}{'Score':<8}{'Level':<10}{'Expected':<10}{'Result':<8}")
    print("-" * 45)
    passed = 0

    for case_id, content, sender, expected in TEST_CASES:
        result = scan_message(content, sender, "English")

        if expected == "High":
            ok = LEVEL_RANK[result.warning_level] >= LEVEL_RANK["High"]
        else:  # expected == "Low"
            ok = LEVEL_RANK[result.warning_level] <= LEVEL_RANK["Medium"]

        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1

        print(f"{case_id:<5}{result.final_risk_score:<8}{result.warning_level:<10}{expected:<10}{status:<8}")

    print("-" * 45)
    print(f"{passed}/{len(TEST_CASES)} passed")


if __name__ == "__main__":
    run()
