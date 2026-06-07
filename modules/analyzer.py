import re

# =========================================
# ADVANCED MAILORA THREAT ANALYZER
# =========================================

def analyze_email(email):

    score = 0

    indicators = []

    detected_links = []

    suspicious_domains = []

    shortened_urls = []

    highlighted_email = email

    attack_type = "Unknown"

    email_lower = email.lower()

    # =========================================
    # PHISHING KEYWORDS
    # =========================================

    phishing_keywords = [

        "urgent",
        "verify",
        "account suspended",
        "click here",
        "login",
        "password",
        "confirm account",
        "bank",
        "security alert",
        "limited access",
        "update account",
        "unauthorized login",
        "verify identity",
        "payment failed",
        "confirm now",
        "verify immediately",
        "reset password",
        "security verification"

    ]

    # =========================================
    # URGENCY WORDS
    # =========================================

    urgency_words = [

        "immediately",
        "within 24 hours",
        "urgent action required",
        "asap",
        "now",
        "limited time",
        "act now",
        "final warning",
        "urgent notice"

    ]

    # =========================================
    # CREDENTIAL HARVESTING
    # =========================================

    credential_words = [

        "verify your password",
        "enter your credentials",
        "confirm your login",
        "verify your account",
        "submit your password",
        "login verification",
        "confirm your banking pin"

    ]

    # =========================================
    # IMPERSONATION DETECTION
    # =========================================

    impersonation_words = [

        "microsoft",
        "paypal",
        "maybank",
        "cimb",
        "bank negara",
        "google security",
        "apple support",
        "facebook security"

    ]

    # =========================================
    # PHISHING KEYWORD DETECTION
    # =========================================

    for word in phishing_keywords:

        if word in email_lower:

            score += 8

            indicators.append(
                f"Suspicious keyword detected: {word}"
            )

            highlighted_email = re.sub(

                word,

                f"<span class='highlight-keyword'>{word}</span>",

                highlighted_email,

                flags=re.IGNORECASE

            )

    # =========================================
    # URGENCY DETECTION
    # =========================================

    for word in urgency_words:

        if word in email_lower:

            score += 12

            indicators.append(
                "Urgency language detected"
            )

            highlighted_email = re.sub(

                word,

                f"<span class='highlight-urgency'>{word}</span>",

                highlighted_email,

                flags=re.IGNORECASE

            )

    # =========================================
    # CREDENTIAL DETECTION
    # =========================================

    for word in credential_words:

        if word in email_lower:

            score += 18

            indicators.append(
                "Credential harvesting attempt detected"
            )

            highlighted_email = re.sub(

                word,

                f"<span class='highlight-credential'>{word}</span>",

                highlighted_email,

                flags=re.IGNORECASE

            )

    # =========================================
    # IMPERSONATION DETECTION
    # =========================================

    for word in impersonation_words:

        if word in email_lower:

            score += 10

            indicators.append(
                f"Possible impersonation detected: {word}"
            )

            highlighted_email = re.sub(

                word,

                f"<span class='highlight-impersonation'>{word}</span>",

                highlighted_email,

                flags=re.IGNORECASE

            )

    # =========================================
    # URL EXTRACTION
    # =========================================

    urls = re.findall(

        r'(https?://[^\s]+)',

        email

    )

    risky_domains = [

        "bit.ly",
        "tinyurl",
        "rb.gy",
        "goo.gl",
        "ow.ly",
        "shorturl",
        "grabify",
        "fake-login",
        "secure-verification",
        "freegift",
        "confirm-account",
        "security-check"

    ]

    if urls:

        detected_links = urls

        score += 25

        indicators.append(
            "Suspicious URL detected"
        )

        for link in urls:

            highlighted_email = highlighted_email.replace(

                link,

                f"<span class='highlight-url'>{link}</span>"

            )

            link_lower = link.lower()

            # SHORTENED URL DETECTION

            if any(short in link_lower for short in [

                "bit.ly",
                "tinyurl",
                "rb.gy",
                "goo.gl",
                "ow.ly"

            ]):

                shortened_urls.append(link)

                score += 15

                indicators.append(
                    "Shortened URL detected"
                )

            # RISKY DOMAIN DETECTION

            for domain in risky_domains:

                if domain in link_lower:

                    suspicious_domains.append(link)

                    score += 20

                    indicators.append(
                        f"Suspicious domain detected: {domain}"
                    )

    # =========================================
    # ATTACK TYPE DETECTION
    # =========================================

    if "bank" in email_lower:

        attack_type = "Banking Phishing"

    elif "password" in email_lower:

        attack_type = "Credential Theft"

    elif "payment" in email_lower:

        attack_type = "Financial Scam"

    elif "security alert" in email_lower:

        attack_type = "Security Impersonation"

    elif shortened_urls:

        attack_type = "Malicious URL Redirection"

    else:

        attack_type = "General Phishing"

    # =========================================
    # SCORE LIMIT
    # =========================================

    if score > 100:

        score = 100

    # =========================================
    # THREAT CLASSIFICATION
    # =========================================

    if score >= 70:

        result = "Critical Risk"

    elif score >= 40:

        result = "High Risk"

    elif score >= 20:

        result = "Suspicious"

    else:

        result = "Safe"

    # =========================================
    # AI EXPLANATION
    # =========================================

    if result == "Critical Risk":

        explanation = """

        This email contains multiple phishing indicators,
        suspicious URLs,
        shortened redirect links,
        urgency manipulation language,
        and credential harvesting attempts commonly
        associated with advanced phishing attacks.

        """

        recommendation = """

        Avoid clicking links or downloading attachments.
        Immediately delete the email,
        block the sender,
        and report the phishing attempt
        to cybersecurity personnel.

        """

    elif result == "High Risk":

        explanation = """

        This email demonstrates strong phishing-related behavior
        and contains suspicious characteristics
        capable of compromising sensitive information.

        """

        recommendation = """

        Verify the sender identity manually
        and avoid interacting with suspicious links
        or credential requests.

        """

    elif result == "Suspicious":

        explanation = """

        Several suspicious behaviors were detected
        during analysis.
        Additional verification is strongly recommended
        before taking further action.

        """

        recommendation = """

        Proceed cautiously
        and verify all URLs,
        sender information,
        and login requests independently.

        """

    else:

        explanation = """

        No major phishing indicators were detected
        within the submitted email content
        based on current Mailora threat intelligence analysis.

        """

        recommendation = """

        The email currently appears safe,
        but users should continue practicing
        cybersecurity awareness.

        """

    # =========================================
    # RETURN ANALYSIS
    # =========================================

    return {

        "score": score,

        "result": result,

        "attack_type": attack_type,

        "explanation": explanation,

        "recommendation": recommendation,

        "indicators": indicators,

        "detected_links": detected_links,

        "suspicious_domains": suspicious_domains,

        "shortened_urls": shortened_urls,

        "highlighted_email": highlighted_email

    }