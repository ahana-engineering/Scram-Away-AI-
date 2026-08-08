"""
Core detection engine for the AI-powered SMS/Email phishing detection platform.

Implements a three-tier escalation pipeline:
  Tier 1 - Fast rule-based / heuristic filter (URLs, sender patterns, keywords)
  Tier 2 - Lightweight pattern/category scoring ("ML-style" classifier)
  Tier 3 - LLM reasoning via Gemini API (zero-day detection + explainability)

Then aggregates all tier outputs into a single risk score, warning level,
and human-readable explanation -- with a safety floor so a strong signal
from any one tier can't get diluted away by averaging (this was the bug
found in the original TypeScript version).
"""

import os
import re
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Tier1Result:
    risk_score: int
    flags: List[str] = field(default_factory=list)


@dataclass
class Tier2Result:
    risk_score: int
    detected_categories: Dict[str, bool] = field(default_factory=dict)


@dataclass
class Tier3Result:
    tier3_ran: bool
    risk_score: Optional[int] = None
    flagged_signals: List[str] = field(default_factory=list)
    explanation: str = ""
    recommended_action: str = ""
    intent_analysis: str = ""


@dataclass
class ScanResult:
    final_risk_score: int
    warning_level: str
    flagged_signals: List[str]
    explanation: str
    recommended_action: str
    executed_tiers: Dict[str, bool]
    tier1: Tier1Result
    tier2: Tier2Result
    tier3: Optional[Tier3Result]


# ---------------------------------------------------------------------------
# Tier 1: rule-based filter
# ---------------------------------------------------------------------------

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}

SUSPICIOUS_KEYWORDS = [
    # English
    "blocked", "block", "verify", "kyc", "urgent", "immediately",
    "suspend", "suspended", "click here", "otp", "pin", "account will be",
    "act now", "final notice", "expire", "won", "prize", "claim now",
    "reactivate", "limited time", "lucky draw", "lottery", "reward",
    "cashback offer", "congratulations", "maintenance", "fine",
    # Hindi (Devanagari)
    "ब्लॉक", "तुरंत", "सत्यापित", "खाता बंद", "अभी क्लिक करें", "पुरस्कार",
    "बधाई", "जल्दी करें", "अंतिम चेतावनी",
    # Hindi (Latin/Hinglish)
    "turant", "jaldi karein", "khata band", "block ho jayega", "verify karein",
    "kyc update", "inaam", "badhai ho",
    # Tamil
    "தடுக்கப்படும்", "சரிபார்க்கவும்", "உடனடியாக", "பரிசு", "வாழ்த்துக்கள்",
    "இறுதி எச்சரிக்கை", "இப்போதே",
]

URL_PATTERN = re.compile(
    r"(https?://[^\s]+|www\.[^\s]+|[a-z0-9.-]+\.(?:com|net|org|in|co|link|win)[^\s]*)",
    re.IGNORECASE,
)


def run_tier1(content: str, sender: str) -> Tier1Result:
    flags = []
    score = 0
    lower = content.lower()

    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]
    if hits:
        score += min(50, 10 * len(hits))
        flags.append(f"Risk Rule Trigger: Suspicious keywords ({', '.join(hits[:4])})")

    urls = URL_PATTERN.findall(content)
    for url in urls:
        domain_match = re.search(r"([a-z0-9.-]+)\.[a-z]{2,}", url, re.IGNORECASE)
        domain = domain_match.group(0).lower() if domain_match else url.lower()

        if any(short in domain for short in SHORTENER_DOMAINS):
            score += 25
            flags.append("Risk Rule Trigger: Shortened/obscured link detected")

        # Lookalike / multi-subdomain trick, e.g. bank.co.in.randomdomain.net
        if len(domain.split(".")) > 3:
            score += 30
            flags.append("Risk Rule Trigger: Suspicious multi-subdomain (lookalike domain) pattern")

    if sender:
        s = sender.strip()
        if re.match(r"^[A-Z]{2}-[A-Z0-9]{6}$", s):
            pass  # looks like a legitimate registered DLT header, no penalty
        elif re.match(r"^\+?\d{10,13}$", s):
            score += 10
            flags.append("Risk Rule Trigger: Sender is a raw phone number, not a registered ID")

    return Tier1Result(risk_score=min(100, score), flags=flags)


# ---------------------------------------------------------------------------
# Tier 2: lightweight category / pattern scoring ("ML-style")
# ---------------------------------------------------------------------------

CATEGORY_PATTERNS = {
    "urgencyLanguage": [
        r"\bwithin \d+ ?(hour|hr|minute|min)s?\b", r"\bimmediately\b", r"\burgent\b",
        r"\bact now\b", r"\bfinal (notice|warning)\b", r"\bexpire[sd]? (today|soon)\b",
        r"तुरंत", r"जल्दी", r"अभी", r"உடனடியாக", r"இப்போதே",
    ],
    "authorityImpersonation": [
        r"\bbank\b", r"\brbi\b", r"\bincome tax\b", r"\bgovernment\b", r"\bpolice\b",
        r"\bcyber ?crime\b", r"\bcustoms\b", r"\bcourier\b",
        r"बैंक", r"सरकार", r"पुलिस", r"வங்கி", r"அரசு", r"காவல்",
    ],
    "credentialOTPRequest": [
        r"\botp\b", r"\bpin\b", r"\bcvv\b", r"\bpassword\b", r"\bverify your\b",
        r"\bconfirm your (account|details)\b",
        r"सत्यापित करें", r"पासवर्ड", r"சரிபார்க்கவும்", r"கடவுச்சொல்",
    ],
    "financialUPIAction": [
        r"\bupi\b", r"\bcollect request\b",
        r"\brefund\b.{0,40}\b(verify|confirm|link|otp|pin|account number|card number)\b",
        r"\b(verify|confirm|link|update)\b.{0,40}\bupi\s*pin\b",
        r"\btransfer\b.{0,40}\b(otp|pin|verify)\b",
        r"\bpending amount\b.{0,40}\b(verify|link|pay now)\b",
        r"भुगतान", r"रिफंड", r"பணம் செலுத்த", r"பணம் திரும்ப",
    ],
    "apkOrMalwareLink": [
        r"\.apk\b", r"\bdownload (the )?app\b", r"\binstall\b",
    ],
    "prizeOrLotteryScam": [
        r"\bwon\b", r"\bclaim now\b", r"\blucky draw\b", r"\blottery\b",
        r"\bprize\b", r"\bcongratulations\b", r"\breward\b",
        r"पुरस्कार", r"बधाई", r"இனாம்", r"வாழ்த்துக்கள்",
    ],
}

CATEGORY_WEIGHT = 18


def run_tier2(content: str) -> Tier2Result:
    lower = content.lower()
    detected = {}
    score = 0

    for category, patterns in CATEGORY_PATTERNS.items():
        matched = any(re.search(p, lower) for p in patterns)
        detected[category] = matched
        if matched:
            score += CATEGORY_WEIGHT

    return Tier2Result(risk_score=min(100, score), detected_categories=detected)


# ---------------------------------------------------------------------------
# Tier 3: LLM reasoning (Gemini) -- zero-day detection + explainability
# ---------------------------------------------------------------------------

TIER3_PROMPT_TEMPLATE = """You are a fraud detection reasoning engine analyzing a message for phishing or scam intent.

Message content:
\"\"\"{content}\"\"\"

Sender: {sender}
Language: {language}

Analyze the INTENT of this message. Consider: does it ask the recipient to reveal
credentials/OTP, does it manufacture urgency around a plausible recent action, does
it discourage normal verification, does it impersonate an authority, does it request
money/UPI action, does it use a suspicious/lookalike link.

IMPORTANT CALIBRATION -- avoid false positives on routine legitimate messages:
Ordinary business urgency is NOT by itself a scam signal. Delivery/address
confirmations, order cancellation deadlines, subscription renewal reminders, OTP
delivery messages, and refund/payment confirmations are extremely common and
legitimate, even when they mention a deadline or a small action needed. Only treat
urgency as a red flag when it is combined with at least one of: a request for
credentials/OTP/PIN/CVV, a suspicious or lookalike domain, impersonation of a bank
or government authority, discouragement from verifying through normal channels, or
a request to install/download something. A message that simply asks the user to
confirm an address, view an order, or note a routine deadline -- with no credential
request and no suspicious domain -- should score LOW, not high, even if it mentions
"hours" or "immediately" or "refund".

Respond with ONLY valid JSON, no markdown formatting, no extra text, matching exactly
this schema:
{{
  "risk_score": <integer 0-100, your confident numeric assessment matching your explanation>,
  "warning_level": "<Low|Medium|High|Critical>",
  "flagged_signals": ["<short red flag 1>", "<short red flag 2>"],
  "explanation": "<plain language explanation in {language}, 2-3 sentences>",
  "recommended_action": "<concrete next step for the user, in {language}>",
  "intent_analysis": "<one sentence on what the message is actually trying to get the user to do>"
}}

IMPORTANT: risk_score MUST be numerically consistent with your explanation and
warning_level. If your explanation says this is high-risk phishing, risk_score must
be 70 or above. If your explanation says this looks safe/legitimate, risk_score must
be below 25.
"""


def run_tier3(content: str, sender: str, language: str) -> Tier3Result:
    """Calls Gemini for deep reasoning. Requires GEMINI_API_KEY env var.
    Returns tier3_ran=False if no key is set or the call fails, so the
    pipeline degrades gracefully instead of crashing."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return Tier3Result(tier3_ran=False)

    try:
        from google import genai

        client = genai.Client(api_key=api_key)

        prompt = TIER3_PROMPT_TEMPLATE.format(content=content, sender=sender, language=language)
        response = client.models.generate_content(model="gemini-flash-latest", contents=prompt)
        raw_text = response.text.strip()

        # Strip markdown code fences if the model added them anyway
        raw_text = re.sub(r"^```json\s*|\s*```$", "", raw_text.strip())

        data = json.loads(raw_text)

        return Tier3Result(
            tier3_ran=True,
            risk_score=int(data.get("risk_score", 0)),
            flagged_signals=data.get("flagged_signals", []),
            explanation=data.get("explanation", ""),
            recommended_action=data.get("recommended_action", ""),
            intent_analysis=data.get("intent_analysis", ""),
        )
    except Exception as e:
        print(f"[Tier 3] Gemini call failed, falling back to Tier 1/2 only: {e}")
        return Tier3Result(tier3_ran=False)


# ---------------------------------------------------------------------------
# Aggregation (with the fix applied)
# ---------------------------------------------------------------------------

def aggregate(
    language: str,
    tier1: Tier1Result,
    tier2: Tier2Result,
    tier3: Tier3Result,
) -> ScanResult:
    executed_tiers = {"tier1": True, "tier2": True, "tier3": tier3.tier3_ran}

    if tier3.tier3_ran and tier3.risk_score is not None:
        final_score = round(tier3.risk_score * 0.7 + tier2.risk_score * 0.2 + tier1.risk_score * 0.1)
    elif tier1.risk_score >= 80:
        final_score = max(tier1.risk_score, tier2.risk_score)
    else:
        final_score = round(tier2.risk_score * 0.6 + tier1.risk_score * 0.4)

    # Safety floor: a strong individual signal from ANY tier should not
    # get diluted below a reasonable threshold by the weighted average.
    strongest_signal = max(tier1.risk_score, tier2.risk_score, tier3.risk_score or 0)
    if strongest_signal >= 80:
        final_score = max(final_score, 70)

    final_score = min(100, max(0, final_score))

    if final_score >= 85:
        warning_level = "Critical"
    elif final_score >= 55:
        warning_level = "High"
    elif final_score >= 25:
        warning_level = "Medium"
    else:
        warning_level = "Low"

    flags = list(tier1.flags)
    category_labels = {
        "urgencyLanguage": "ML Vector: Urgent threat or deadline pressure",
        "authorityImpersonation": "ML Vector: Authority or bank impersonation pattern",
        "credentialOTPRequest": "ML Vector: Request for OTP or sensitive credentials",
        "financialUPIAction": "ML Vector: Financial request or UPI collect trap",
        "apkOrMalwareLink": "ML Vector: Malicious APK/app download link",
        "prizeOrLotteryScam": "ML Vector: Fake prize, lottery, or reward scam pattern",
    }
    for cat, matched in tier2.detected_categories.items():
        if matched:
            flags.append(category_labels.get(cat, f"ML Vector: {cat}"))

    for s in tier3.flagged_signals:
        if s not in flags:
            flags.append(s)

    explanation = tier3.explanation or default_explanation(warning_level, language, flags)
    action = tier3.recommended_action or default_action(warning_level, language)

    return ScanResult(
        final_risk_score=final_score,
        warning_level=warning_level,
        flagged_signals=flags,
        explanation=explanation,
        recommended_action=action,
        executed_tiers=executed_tiers,
        tier1=tier1,
        tier2=tier2,
        tier3=tier3,
    )


def default_explanation(level: str, lang: str, flags: List[str]) -> str:
    flag_text = "; ".join(flags) if flags else "No major red flags detected."

    if lang == "Hindi":
        if level in ("Critical", "High"):
            return f"यह संदेश धोखाधड़ी (स्कैम) के मजबूत संकेत दिखाता है। मुख्य चेतावनी संकेत: {flag_text}। कृपया किसी लिंक पर क्लिक न करें या अपनी जानकारी साझा न करें।"
        if level == "Medium":
            return f"इस संदेश में सावधानी बरतने की आवश्यकता है: {flag_text}। आगे बढ़ने से पहले स्वतंत्र रूप से पुष्टि करें।"
        return "यह संदेश सुरक्षित प्रतीत होता है। कोई गंभीर धोखाधड़ी संकेत नहीं मिला।"

    if lang == "Tamil":
        if level in ("Critical", "High"):
            return f"இந்த செய்தி மோசடிக்கான வலுவான அறிகுறிகளைக் காட்டுகிறது. முக்கிய எச்சரிக்கை அறிகுறிகள்: {flag_text}. தயவுசெய்து இணைப்புகளைக் கிளிக் செய்யவோ உங்கள் தகவல்களைப் பகிரவோ வேண்டாம்."
        if level == "Medium":
            return f"இந்த செய்திக்கு எச்சரிக்கை தேவை: {flag_text}. தொடர்வதற்கு முன் சுயாதீனமாக சரிபார்க்கவும்."
        return "இந்த செய்தி பாதுகாப்பானதாகத் தெரிகிறது. கடுமையான மோசடி அறிகுறிகள் எதுவும் கண்டறியப்படவில்லை."

    # English default
    if level in ("Critical", "High"):
        return f"This message contains strong indicators of phishing or fraud. Key red flags: {flag_text}. Do not click links or share credentials."
    if level == "Medium":
        return f"This message requires caution: {flag_text}. Verify independently before acting."
    return "This message appears low-risk. No major scam indicators were detected."


def default_action(level: str, lang: str) -> str:
    if lang == "Hindi":
        if level in ("Critical", "High"):
            return "1. किसी भी लिंक पर क्लिक न करें। 2. OTP/PIN साझा न करें। 3. cybercrime.gov.in पर रिपोर्ट करें या 1930 पर कॉल करें।"
        return "आधिकारिक ऐप या सत्यापित ग्राहक सेवा नंबर के माध्यम से सीधे पुष्टि करें।"

    if lang == "Tamil":
        if level in ("Critical", "High"):
            return "1. எந்த இணைப்பையும் கிளிக் செய்ய வேண்டாம். 2. OTP/PIN பகிர வேண்டாம். 3. cybercrime.gov.in இல் புகாரளிக்கவும் அல்லது 1930 ஐ அழைக்கவும்."
        return "அதிகாரப்பூர்வ செயலி அல்லது சரிபார்க்கப்பட்ட வாடிக்கையாளர் சேவை எண் மூலம் நேரடியாக உறுதிப்படுத்தவும்."

    # English default
    if level in ("Critical", "High"):
        return "Do not click any links or share OTP/PIN. Report to cybercrime.gov.in or call 1930."
    return "Verify directly through the official app or a verified customer service number."


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------

def scan_message(content: str, sender: str = "Unknown", language: str = "English") -> ScanResult:
    tier1 = run_tier1(content, sender)
    tier2 = run_tier2(content)

    # Escalate to Tier 3 unless the message is completely clean at both
    # Tier 1 and Tier 2 (no signals at all). This is safer than escalating
    # only within a narrow score band -- a scam with subtle phrasing that
    # scores low on rigid keyword rules still deserves a chance at Tier 3's
    # semantic reasoning, which is the whole point of having that tier.
    should_escalate = not (tier1.risk_score == 0 and tier2.risk_score == 0)
    tier3 = run_tier3(content, sender, language) if should_escalate else Tier3Result(tier3_ran=False)

    return aggregate(language, tier1, tier2, tier3)
