# =========================================
# IMPORTS
# =========================================

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file
)

import sqlite3
import re
import pandas as pd
import random

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

from io import BytesIO
from datetime import datetime
from functools import wraps
from collections import Counter

# =========================================
# REPORTLAB PDF
# =========================================

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

# =========================================
# FLASK APP
# =========================================

app = Flask(__name__)
app.secret_key = "mailora_secret"
phishing_df = pd.read_csv(
    "datasets/phishing_email.csv",
    low_memory=False
)

# =========================================
# SESSION INITIALIZATION
# =========================================

@app.before_request
def initialize_session():

    if "completed_modules" not in session:

        session["completed_modules"] = []

# =========================================
# DATABASE
# =========================================

DATABASE = "database.db"

# =========================================
# DATABASE INITIALIZATION
# =========================================

def init_db():

    db = sqlite3.connect(DATABASE)

    cursor = db.cursor()

    # USERS TABLE

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        fullname TEXT NOT NULL,

        username TEXT UNIQUE NOT NULL,

        contact TEXT NOT NULL,

        password TEXT NOT NULL

    )

    """)

    # HISTORY TABLE

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS history (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT,

        url TEXT,

        email_content TEXT,

        result TEXT,

        score INTEGER,

        created_at TEXT

    )

    """)

    # ADD NOTES COLUMN IF NOT EXISTS

    try:

        cursor.execute(
            "ALTER TABLE history ADD COLUMN notes TEXT"
    )

    except:

        pass

    # SUPPORT REQUESTS TABLE

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS support_requests (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT,

        name TEXT,

        email TEXT,

        category TEXT,

        message TEXT,

        status TEXT,

        created_at TEXT

    )

""")

    db.commit()
    db.close()

init_db()
# =========================================
# PHISHING ML MODEL
# =========================================

print("Loading phishing dataset...")

phishing_df = pd.read_csv(
    "datasets/phishing_email.csv"
)

vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

X = vectorizer.fit_transform(
    phishing_df["text_combined"]
)

y = phishing_df["label"]

model = MultinomialNB()

model.fit(X, y)

print("ML Model Ready")

# =========================================
# DATABASE CONNECTION
# =========================================

def get_db():

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row

    return conn

# =========================================
# LOGIN REQUIRED
# =========================================

def login_required(f):

    @wraps(f)

    def decorated_function(*args, **kwargs):

        if "user" not in session:

            return redirect("/")

        return f(*args, **kwargs)

    return decorated_function

# =========================================
# GLOBAL REPORT
# =========================================

latest_report = {}

# =========================================
# LOGIN
# =========================================

@app.route("/", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        login_input = request.form["login"]
        password = request.form["password"]

        db = get_db()
        cursor = db.cursor()

        cursor.execute(

            """
            SELECT *
            FROM users
            WHERE (username=? OR contact=?)
            AND password=?
            """,

            (
                login_input,
                login_input,
                password
            )

        )

        user = cursor.fetchone()

        if user:

            session["user"] = user["username"]

            return redirect("/dashboard")

        else:

            error = "Invalid username or password"

    return render_template(

        "login.html",
        error=error

    )

# =========================================
# REGISTER
# =========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    error = None

    if request.method == "POST":

        fullname = request.form["fullname"]
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # PASSWORD VALIDATION

        if len(password) < 8:

            error = "Password must contain at least 8 characters"

        elif not re.search(r"\d", password):

            error = "Password must contain at least 1 number"

        elif not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):

            error = "Password must contain at least 1 special character"

        elif password != confirm_password:

            error = "Passwords do not match"

        else:

            db = get_db()
            cursor = db.cursor()

            cursor.execute(

                """
                SELECT *
                FROM users
                WHERE username=?
                """,

                (username,)

            )

            existing_user = cursor.fetchone()

            if existing_user:

                error = "Username already exists"

            else:

                cursor.execute(

                    """
                    INSERT INTO users
                    (
                        fullname,
                        username,
                        contact,
                        password
                    )
                    VALUES (?, ?, ?, ?)
                    """,

                    (
                        fullname,
                        username,
                        email,
                        password
                    )

                )

                db.commit()
                db.close()

                return redirect("/")

    return render_template(

        "register.html",
        error=error

    )

# =========================================
# DASHBOARD
# =========================================

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        SELECT COUNT(*)
        FROM history
        WHERE username=?
        """,

        (session["user"],)

    )

    total_cases = cursor.fetchone()[0]

    cursor.execute(

        """
        SELECT COUNT(*)
        FROM history
        WHERE username=?
        AND result='High Risk'
        """,

        (session["user"],)

    )

    high_risk = cursor.fetchone()[0]

    cursor.execute(

        """
        SELECT COUNT(*)
        FROM history
        WHERE username=?
        AND result='Safe'
        """,

        (session["user"],)

    )

    safe_cases = cursor.fetchone()[0]
    cursor.execute(

    """
    SELECT COUNT(*)
    FROM history
    WHERE username=?
    AND result='Critical'
    """,

    (session["user"],)

)

    critical_cases = cursor.fetchone()[0]
    cursor.execute(

    """
    SELECT AVG(score)
    FROM history
    WHERE username=?
    """,

    (session["user"],)

)

    avg_score = cursor.fetchone()[0]

    if avg_score is None:

        avg_score = 0

    avg_score = round(avg_score)

    cursor.execute(

    """
    SELECT *
    FROM history
    WHERE username=?
    ORDER BY id DESC
    LIMIT 5
    """,

    (session["user"],)

)

    recent_cases = cursor.fetchall()


    # =========================================
    # WEEKLY INVESTIGATION DATA
    # =========================================

    cursor.execute(

        """
        SELECT created_at
        FROM history
        WHERE username=?
        """,

        (session["user"],)

    )

    all_dates = cursor.fetchall()

    weekday_counter = Counter()

    for row in all_dates:

        try:

            date_obj = datetime.strptime(
                row["created_at"],
                "%d %B %Y %H:%M:%S"
            )

            weekday = date_obj.strftime("%a")

            weekday_counter[weekday] += 1

        except:

            pass

    weekly_data = [

        weekday_counter.get("Mon", 0),
        weekday_counter.get("Tue", 0),
        weekday_counter.get("Wed", 0),
        weekday_counter.get("Thu", 0),
        weekday_counter.get("Fri", 0),
        weekday_counter.get("Sat", 0),
        weekday_counter.get("Sun", 0)

    ]

    cursor.execute(

        """
        SELECT COUNT(*)
        FROM history
        WHERE username=?
        AND result='Medium Risk'
        """,

    (session["user"],)

)

    medium_risk = cursor.fetchone()[0]

    cursor.execute(

    """
    SELECT COUNT(*)
    FROM history
    WHERE username=?
    AND result='Low Risk'
    """,

    (session["user"],)

)

    low_risk = cursor.fetchone()[0]

    db.close()

    return render_template(

    "dashboard.html",

    total_cases=total_cases,
    high_risk=high_risk,
    safe_cases=safe_cases,
    critical_cases=critical_cases,
    avg_score=avg_score,
    recent_cases=recent_cases,
    medium_risk=medium_risk,
    low_risk=low_risk,
    weekly_data=weekly_data

)

# =========================================
# THREAT ANALYZER
# =========================================

@app.route("/home")
@login_required
def home():

    return render_template("home.html")

# =========================================
# ANALYZE
# =========================================

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():

    global latest_report

    url = request.form.get("url", "")
    email_content = request.form["email_content"]

    # =========================================
# MACHINE LEARNING ANALYSIS
# =========================================

    analysis_text = (
        email_content + " " + url
    )

    X_test = vectorizer.transform(
        [analysis_text]
    )

    prediction = model.predict(
        X_test
    )[0]

    probability = model.predict_proba(
        X_test
    )[0]

    confidence = round(
        max(probability) * 100
    )

    if prediction == 0:

        score = max(
            0,
            100 - confidence
        )

    else:

        score = confidence


    if score <= 20:

        result = "Safe"

    elif score <= 40:

        result = "Low Risk"

    elif score <= 60:

        result = "Medium Risk"

    elif score <= 80:

        result = "High Risk"

    else:

        result = "Critical"

    latest_report = {

        "url": url,
        "email_content": email_content,
        "score": score,
        "result": result,
        "timestamp": datetime.now().strftime(
            "%d %B %Y %H:%M:%S"
        )

    }

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        INSERT INTO history
        (
            username,
            url,
            email_content,
            result,
            score,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,

        (
            session["user"],
            url,
            email_content,
            result,
            score,
            datetime.now().strftime(
                "%d %B %Y %H:%M:%S"
            )
        )

    )

    db.commit()

    case_id = cursor.lastrowid

    db.close()

    return redirect(f"/result/{case_id}")

# =========================================
# RESULT
# =========================================

@app.route("/result/<int:id>")
@login_required
def result(id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        SELECT *
        FROM history
        WHERE id=?
        """,

        (id,)

    )

    case = cursor.fetchone()

    db.close()

    return render_template(

        "result.html",
        case=case

    )

# =========================================
# SAVE INVESTIGATION NOTES
# =========================================

@app.route("/save_note/<int:id>", methods=["POST"])
@login_required
def save_note(id):

    notes = request.form.get(
        "notes"
    )

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        UPDATE history
        SET notes=?
        WHERE id=?
        """,

        (
            notes,
            id
        )

    )

    db.commit()
    db.close()

    return redirect(
        f"/result/{id}"
    )

# =========================================
# EXPORT PDF REPORT
# =========================================

@app.route("/export_case_pdf/<int:id>")
@login_required
def export_case_pdf(id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        SELECT *
        FROM history
        WHERE id=?
        """,

        (id,)

    )

    case = cursor.fetchone()

    db.close()

    # =========================================
    # RECOMMENDATION
    # =========================================

    recommendation = ""

    if case["result"] == "Safe":

        recommendation = """
        The submitted content appears legitimate and
        does not exhibit significant phishing indicators.
        Continue following standard cybersecurity practices.
        """

    elif case["result"] == "Low Risk":

        recommendation = """
        Minor suspicious characteristics were detected.
        Users should verify the sender and avoid sharing
        sensitive information unnecessarily.
        """

    elif case["result"] == "Medium Risk":

        recommendation = """
        Several phishing indicators were identified.
        Further verification is recommended before
        interacting with any links or attachments.
        """

    elif case["result"] == "High Risk":

        recommendation = """
        Strong phishing indicators were detected.
        Users should avoid interacting with the content
        and report the message for investigation.
        """

    else:

        recommendation = """
        Critical phishing indicators detected.
        Do not click links, open attachments, or
        disclose credentials. Immediate action is advised.
        """

    buffer = BytesIO()

    pdf = SimpleDocTemplate(
    buffer,
    pagesize=A4
)

    styles = getSampleStyleSheet()

    content = []

    content.append(
    Paragraph(
        "MAILORA CYBER THREAT INVESTIGATION REPORT",
        styles["Title"]
    )
)
    content.append(Spacer(1, 4))

    content.append(Spacer(1, 5))

    content.append(
    Paragraph(
        "CASE INFORMATION",
        styles["Heading2"]
    )
)

    content.append(
    Paragraph(
        f"<b>Case ID:</b> {case['id']}",
        styles["BodyText"]
    )
)

    content.append(
    Paragraph(
        f"<b>Investigator:</b> {case['username']}",
        styles["BodyText"]
    )
)

    content.append(
    Paragraph(
        f"<b>Date:</b> {case['created_at']}",
        styles["BodyText"]
    )
)

    content.append(Spacer(1, 6))

    content.append(
    Paragraph(
        "THREAT SUMMARY",
        styles["Heading2"]
    )
)

    content.append(
    Paragraph(
        f"<b>Risk Level:</b> {case['result']}",
        styles["BodyText"]
    )
)

    content.append(
    Paragraph(
        f"<b>Threat Score:</b> {case['score']}%",
        styles["BodyText"]
    )
)

    content.append(Spacer(1, 6))

    content.append(
    Paragraph(
        "INVESTIGATION EVIDENCE",
        styles["Heading2"]
    )
)

    content.append(
    Paragraph(
        "<b>Suspicious URL</b>",
        styles["BodyText"]
    )
)

    content.append(
    Paragraph(
        str(case["url"]) if case["url"] else "No URL Submitted",
        styles["BodyText"]
    )
)
    content.append(Spacer(1, 6))

    content.append(Spacer(1, 6))

    content.append(
    Paragraph(
        "<b>Submitted Email Content</b>",
        styles["BodyText"]
    )
)

    content.append(
    Paragraph(
        str(case["email_content"]).replace("\n", "<br/>"),
        styles["BodyText"]
    )
)

    content.append(Spacer(1, 6))

    content.append(
        Paragraph(
            "INVESTIGATOR NOTES",
            styles["Heading2"]
        )
    )

    content.append(
        Paragraph(
            str(case["notes"] or "No notes available."),
            styles["Normal"]
        )
    )
    content.append(Spacer(1, 5))

    content.append(
    Paragraph(
        "RECOMMENDATIONS",
        styles["Heading2"]
    )
)

    content.append(
    Paragraph(
        recommendation.strip(),
        styles["BodyText"]
    )
)
    content.append(Spacer(1, 8))

    content.append(
    Paragraph(
        "______________________________________________",
        styles["BodyText"]
    )
)
    content.append(
    Paragraph(
        "Generated by Mailora",
        styles["Heading3"]
    )
)

    content.append(
    Paragraph(
        "Web-Based Phishing Email Detection & Analysis System",
        styles["BodyText"]
    )
)

    content.append(
    Paragraph(
        "Management & Science University (MSU)",
        styles["BodyText"]
    )
)

    pdf.build(content)

    buffer.seek(0)

    return send_file(

        buffer,

        as_attachment=True,

        download_name=f"Mailora_Report_{id}.pdf",

        mimetype="application/pdf"

    )
# =========================================
# HISTORY
# =========================================

@app.route("/history")
@login_required
def history():

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        SELECT *
        FROM history
        WHERE username=?
        ORDER BY id DESC
        """,

        (session["user"],)

    )

    cases = cursor.fetchall()

    db.close()

    return render_template(

        "history.html",
        cases=cases

    )

# =========================================
# DELETE CASE
# =========================================

@app.route("/delete_case/<int:id>")
@login_required
def delete_case(id):

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        DELETE FROM history
        WHERE id=?
        """,

        (id,)

    )

    db.commit()
    db.close()

    return redirect("/history")

# =========================================
# EDIT CASE
# =========================================

@app.route("/edit_case/<int:id>", methods=["GET", "POST"])
@login_required
def edit_case(id):

    db = get_db()
    cursor = db.cursor()

    if request.method == "POST":

        email_content = request.form.get(
            "email_content"
        )

        cursor.execute(

            """
            UPDATE history
            SET email_content=?
            WHERE id=?
            """,

            (email_content, id)

        )

        db.commit()
        db.close()

        return redirect("/history")

    cursor.execute(

        """
        SELECT *
        FROM history
        WHERE id=?
        """,

        (id,)

    )

    case = cursor.fetchone()

    db.close()

    return render_template(
        "edit_case.html",
        case=case
    )

# =========================================
# ACCOUNT
# =========================================

@app.route("/account")
@login_required
def account():

    db = get_db()
    cursor = db.cursor()

    cursor.execute(

        """
        SELECT *
        FROM users
        WHERE username=?
        """,

        (session["user"],)

    )

    user = cursor.fetchone()

    db.close()

    return render_template(

        "account.html",
        user=user

    )
# =========================================
# CHANGE PASSWORD
# =========================================

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():

    message = None

    if request.method == "POST":

        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username=?
            """,
            (session["user"],)
        )

        user = cursor.fetchone()

        if user["password"] != current_password:

            message = "Current password is incorrect."

        elif new_password != confirm_password:

            message = "New passwords do not match."

        else:

            cursor.execute(
                """
                UPDATE users
                SET password=?
                WHERE username=?
                """,
                (
                    new_password,
                    session["user"]
                )
            )

            db.commit()

            message = "Password updated successfully."

        db.close()

    return render_template(
        "change_password.html",
        message=message
    )
# =========================================
# UPDATE PROFILE
# =========================================

@app.route("/update-profile", methods=["GET", "POST"])
@login_required
def update_profile():

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username=?
        """,
        (session["user"],)
    )

    user = cursor.fetchone()

    message = None

    if request.method == "POST":

        fullname = request.form.get("fullname")
        contact = request.form.get("contact")

        cursor.execute(
            """
            UPDATE users
            SET fullname=?,
                contact=?
            WHERE username=?
            """,
            (
                fullname,
                contact,
                session["user"]
            )
        )

        db.commit()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username=?
            """,
            (session["user"],)
        )

        user = cursor.fetchone()

        message = "Profile updated successfully."

    db.close()

    return render_template(
        "update_profile.html",
        user=user,
        message=message
    )
# =========================================
# DELETE ACCOUNT
# =========================================

@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():

    message = None

    if request.method == "POST":

        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        delete_confirmation = request.form.get(
    "delete_confirmation"
)

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username=?
            """,
            (session["user"],)
        )

        user = cursor.fetchone()

        
        if password != confirm_password:

            message = "Passwords do not match."

        elif delete_confirmation != "DELETE":

            message = "Type DELETE to confirm account removal."

        elif password != user["password"]:

            message = "Incorrect password."

        elif password != user["password"]:

            message = "Incorrect password."

        else:

            cursor.execute(
                """
                DELETE FROM users
                WHERE username=?
                """,
                (session["user"],)
            )

            db.commit()

            db.close()

            session.clear()

            return redirect("/")

        db.close()

    return render_template(
        "delete_account.html",
        message=message
    )

# =========================================
# CYBER ACADEMY
# =========================================

@app.route("/academy")
@login_required
def academy():

    return render_template("academy.html")

# =========================================
# ACADEMY DATA
# =========================================

academy_modules = {

1: {

    "title": "Phishing Fundamentals",

    "sections": {

        "1.0 Phishing Basics": {

            "chapters": {

                1: {

                    "title": "1.0.1 What is Phishing",

                    "content": """

Phishing is a cyber attack technique used by attackers to deceive individuals into revealing sensitive information such as usernames, passwords, banking credentials, and authentication codes. These attacks commonly impersonate trusted organizations including Microsoft, banks, and enterprise systems in order to manipulate victims into believing the communication is legitimate.

                    """,

                    "category": "Credential Deception",
                    "risk": "High",
                    "vector": "Email Based"

                },

                2: {

                    "title": "1.0.2 Purpose of Phishing Attacks",

                    "content": """

The primary objective of phishing attacks is to gain unauthorized access to sensitive information or enterprise systems. Attackers often use phishing to steal financial data, compromise corporate accounts, distribute malware, or conduct further cyber attacks within organizational environments.

                    """,

                    "category": "Cyber Intrusion",
                    "risk": "Critical",
                    "vector": "Social Engineering"

                },

                3: {

                    "title": "1.0.3 Common Phishing Targets",

                    "content": """

Cybercriminals frequently target employees, finance departments, enterprise administrators, students, and online banking users because these individuals often possess valuable credentials or sensitive organizational information that can be exploited for malicious purposes.

                    """,

                    "category": "Target Profiling",
                    "risk": "Medium",
                    "vector": "Identity Exploitation"

                },

                4: {

                    "title": "1.0.4 Enterprise Impact",

                    "content": """

Successful phishing attacks can lead to severe enterprise consequences including financial loss, data breaches, operational disruption, reputational damage, and unauthorized access to confidential corporate systems and communications.

                    """,

                    "category": "Enterprise Threat",
                    "risk": "Critical",
                    "vector": "Operational Compromise"

                },

                5: {

                    "title": "1.0.5 Real World Phishing Cases",

                    "content": """

Real-world phishing incidents have affected multinational organizations, government agencies, and financial institutions worldwide. Attackers frequently exploit employee trust and weak cybersecurity awareness to compromise enterprise infrastructure and steal confidential data.

                    """,

                    "category": "Threat Intelligence",
                    "risk": "Critical",
                    "vector": "Credential Exploitation"

                }

            }

        },

        "1.1 Phishing Techniques": {

            "chapters": {

                6: {

                    "title": "1.1.1 Email Spoofing",

                    "content": """

Email spoofing allows attackers to forge sender identities and impersonate trusted organizations or enterprise personnel in order to increase phishing credibility and deceive recipients into trusting malicious communications.

                    """,

                    "category": "Identity Spoofing",
                    "risk": "High",
                    "vector": "Email Forgery"

                },

                7: {

                    "title": "1.1.2 Credential Harvesting",

                    "content": """

Credential harvesting attacks redirect victims to fake login portals that mimic legitimate enterprise systems in order to capture usernames, passwords, authentication tokens, and confidential user credentials.

                    """,

                    "category": "Credential Theft",
                    "risk": "Critical",
                    "vector": "Fake Login Portals"

                },

                8: {

                    "title": "1.1.3 Fake Attachments",

                    "content": """

Malicious attachments are frequently distributed through phishing emails disguised as invoices, HR documents, or enterprise reports. These attachments often contain malware, ransomware, or malicious scripts.

                    """,

                    "category": "Malware Delivery",
                    "risk": "Critical",
                    "vector": "Malicious Attachment"

                },

                9: {

                    "title": "1.1.4 Link Manipulation",

                    "content": """

Attackers manipulate URLs and hyperlinks to redirect users toward malicious phishing infrastructure while disguising the destination as legitimate enterprise websites or trusted online services.

                    """,

                    "category": "URL Deception",
                    "risk": "High",
                    "vector": "Malicious Links"

                },

                10: {

                    "title": "1.1.5 Spear Phishing",

                    "content": """

Spear phishing attacks target specific individuals or enterprise employees using personalized information gathered from social media, leaked databases, and organizational intelligence.

                    """,

                    "category": "Targeted Attack",
                    "risk": "Critical",
                    "vector": "Personalized Phishing"

                }

            }

        },

        "1.2 Reporting & Prevention": {

            "chapters": {

                11: {

                    "title": "1.2.1 Identifying Suspicious Emails",

                    "content": """

Suspicious emails often contain urgent language, fake sender addresses, malicious attachments, grammatical errors, and unusual requests designed to manipulate users into performing dangerous actions.

                    """,

                    "category": "Threat Detection",
                    "risk": "Medium",
                    "vector": "Email Analysis"

                },

                12: {

                    "title": "1.2.2 Reporting Procedures",

                    "content": """

Enterprise reporting procedures allow employees to submit suspicious communications to cybersecurity teams for further investigation and threat intelligence analysis.

                    """,

                    "category": "Incident Reporting",
                    "risk": "Low",
                    "vector": "Security Escalation"

                },

                13: {

                    "title": "1.2.3 Multi-Factor Authentication",

                    "content": """

Multi-factor authentication strengthens enterprise security by requiring additional verification methods beyond passwords, reducing the effectiveness of credential theft attacks.

                    """,

                    "category": "Access Security",
                    "risk": "Low",
                    "vector": "Authentication Protection"

                },

                14: {

                    "title": "1.2.4 Password Security",

                    "content": """

Strong password security policies reduce the risk of credential compromise by encouraging complex passwords, password managers, and regular credential updates.

                    """,

                    "category": "Credential Protection",
                    "risk": "Low",
                    "vector": "Password Hygiene"

                },

                15: {

                    "title": "1.2.5 Cybersecurity Awareness",

                    "content": """

Continuous cybersecurity awareness training improves employee readiness against phishing attacks and strengthens enterprise resilience against social engineering threats.

                    """,

                    "category": "Security Awareness",
                    "risk": "Medium",
                    "vector": "User Education"

                }

            }

        }

    }

},

2: {

"title": "URL Intelligence",

"sections": {

    "2.0 URL Fundamentals": {

        "chapters": {

            1: {

                "title": "2.0.1 Malicious Domains",

                "content": """

Malicious domains are fraudulent websites created by cybercriminals to impersonate legitimate organizations. These domains are commonly used in phishing campaigns to steal credentials, distribute malware, and deceive users into revealing sensitive information.

                """,

                "category": "Malicious Infrastructure",
                "risk": "Critical",
                "vector": "Fraudulent Domain"

            },

            2: {

                "title": "2.0.2 Redirect Attacks",

                "content": """

Redirect attacks automatically forward victims from seemingly legitimate websites to malicious destinations controlled by attackers. These techniques are frequently used to disguise phishing campaigns and bypass user suspicion.

                """,

                "category": "URL Manipulation",
                "risk": "High",
                "vector": "Web Redirect"

            },

            3: {

                "title": "2.0.3 URL Shorteners",

                "content": """

URL shortening services can conceal the true destination of a hyperlink. Attackers frequently abuse shortened URLs to hide phishing pages, malware downloads, and malicious websites from users and security tools.

                """,

                "category": "Link Obfuscation",
                "risk": "Medium",
                "vector": "Shortened URL"

            },

            4: {

                "title": "2.0.4 Suspicious Parameters",

                "content": """

Suspicious URL parameters may contain tracking identifiers, malicious, or redirect instructions. Cybersecurity analysts examine these parameters to identify potential phishing and exploitation attempts.

                """,

                "category": "URL Analysis",
                "risk": "Medium",
                "vector": "Parameter Injection"

            },

            5: {

                "title": "2.0.5 Domain Reputation",

                "content": """

Domain reputation systems evaluate the trustworthiness of websites based on historical activity, security incidents, blacklist records, and threat intelligence databases.

                """,

                "category": "Threat Intelligence",
                "risk": "High",
                "vector": "Reputation Analysis"

            }

        }

    },

    "2.1 Domain Investigation": {

        "chapters": {

            6: {

                "title": "2.1.1 WHOIS Analysis",

                "content": """

WHOIS records provide ownership and registration details about internet domains. Analysts use WHOIS information to investigate suspicious websites and identify threat actors.

                """,

                "category": "Domain Investigation",
                "risk": "Medium",
                "vector": "WHOIS Lookup"

            },

            7: {

                "title": "2.1.2 DNS Records",

                "content": """

DNS records reveal how domains are configured and where they are hosted. Examining DNS data can help identify malicious infrastructure and phishing operations.

                """,

                "category": "Infrastructure Analysis",
                "risk": "Medium",
                "vector": "DNS Enumeration"

            },

            8: {

                "title": "2.1.3 Hosting Providers",

                "content": """

Hosting providers supply the infrastructure used to operate websites. Threat analysts investigate hosting services to determine where malicious domains are deployed.

                """,

                "category": "Infrastructure Intelligence",
                "risk": "Medium",
                "vector": "Hosting Analysis"

            },

            9: {

                "title": "2.1.4 SSL Certificates",

                "content": """

SSL certificates encrypt communication between users and websites. Analysts review certificate information to verify legitimacy and identify suspicious domain activity.

                """,

                "category": "Certificate Analysis",
                "risk": "Low",
                "vector": "SSL Verification"

            },

            10: {

                "title": "2.1.5 Infrastructure Mapping",

                "content": """

Infrastructure mapping identifies relationships between domains, IP addresses, hosting providers, and certificates. This process helps uncover larger phishing networks.

                """,

                "category": "Threat Mapping",
                "risk": "High",
                "vector": "Infrastructure Correlation"

            }

        }

    },

    "2.2 Threat Intelligence": {

        "chapters": {

            11: {

                "title": "2.2.1 Indicators of Compromise",

                "content": """

Indicators of Compromise (IOCs) are artifacts that suggest malicious activity, including domains, IP addresses, URLs, hashes, and suspicious behavioral patterns.

                """,

                "category": "Threat Detection",
                "risk": "High",
                "vector": "IOC Analysis"

            },

            12: {

                "title": "2.2.2 Blacklist Verification",

                "content": """

Blacklist databases contain known malicious domains and infrastructure. Security teams verify suspicious URLs against these databases to assess risk.

                """,

                "category": "Threat Intelligence",
                "risk": "Medium",
                "vector": "Blacklist Lookup"

            },

            13: {

                "title": "2.2.3 Threat Correlation",

                "content": """

Threat correlation combines information from multiple intelligence sources to identify relationships between attacks, infrastructure, and threat actors.

                """,

                "category": "Threat Analysis",
                "risk": "High",
                "vector": "Data Correlation"

            },

            14: {

                "title": "2.2.4 Risk Assessment",

                "content": """

Risk assessment evaluates the likelihood and impact of a cybersecurity threat. Analysts use structured methodologies to prioritize security incidents.

                """,

                "category": "Risk Management",
                "risk": "Medium",
                "vector": "Threat Evaluation"

            },

            15: {

                "title": "2.2.5 Investigation Reporting",

                "content": """

Investigation reports document findings, evidence, indicators, and recommendations. These reports support incident response and organizational decision making.

                """,

                "category": "Incident Documentation",
                "risk": "Low",
                "vector": "Security Reporting"

            }

        }

    }

}
},

    3: {
"title": "Social Engineering",

"sections": {

    "3.0 Human Manipulation": {

        "chapters": {

            1: {
                "title": "3.0.1 Human Psychology",
                "content": """Social engineering attacks exploit human emotions including trust, fear, urgency, curiosity, and authority to manipulate victims into performing actions that compromise security.""",
                "category": "Human Manipulation",
                "risk": "High",
                "vector": "Psychological Attack"
            },

            2: {
                "title": "3.0.2 Trust Exploitation",
                "content": """Attackers establish trust through impersonation and deception before requesting sensitive information or encouraging risky behavior.""",
                "category": "Trust Abuse",
                "risk": "High",
                "vector": "Relationship Exploitation"
            },

            3: {
                "title": "3.0.3 Urgency Tactics",
                "content": """Cybercriminals create a sense of urgency to pressure victims into making decisions without proper verification.""",
                "category": "Psychological Pressure",
                "risk": "High",
                "vector": "Urgency Manipulation"
            },

            4: {
                "title": "3.0.4 Fear Based Attacks",
                "content": """Fear-based social engineering uses threats, warnings, or negative consequences to influence victim behavior.""",
                "category": "Emotional Manipulation",
                "risk": "Medium",
                "vector": "Fear Tactics"
            },

            5: {
                "title": "3.0.5 Authority Impersonation",
                "content": """Attackers often pretend to be executives, managers, or government officials to gain compliance from victims.""",
                "category": "Identity Abuse",
                "risk": "Critical",
                "vector": "Authority Exploitation"
            }

        }

    },

    "3.1 Social Engineering Techniques": {

        "chapters": {

            6: {
                "title": "3.1.1 Executive Impersonation",
                "content": """Executive impersonation attacks convince employees that requests originate from senior management.""",
                "category": "Business Email Compromise",
                "risk": "Critical",
                "vector": "Executive Spoofing"
            },

            7: {
                "title": "3.1.2 Pretexting",
                "content": """Pretexting involves creating a believable scenario to obtain confidential information from a target.""",
                "category": "Identity Deception",
                "risk": "High",
                "vector": "Fabricated Scenario"
            },

            8: {
                "title": "3.1.3 Baiting",
                "content": """Baiting attacks lure victims with attractive offers, rewards, or free resources that lead to compromise.""",
                "category": "Enticement Attack",
                "risk": "High",
                "vector": "Malicious Incentive"
            },

            9: {
                "title": "3.1.4 Tailgating",
                "content": """Tailgating occurs when unauthorized individuals gain physical access by following authorized personnel.""",
                "category": "Physical Security",
                "risk": "Medium",
                "vector": "Unauthorized Entry"
            },

            10: {
                "title": "3.1.5 Quid Pro Quo",
                "content": """Attackers offer assistance or benefits in exchange for information or access.""",
                "category": "Information Exchange",
                "risk": "Medium",
                "vector": "False Assistance"
            }

        }

    },

    "3.2 Enterprise Defense": {

        "chapters": {

            11: {
                "title": "3.2.1 Verification Procedures",
                "content": """Verification procedures ensure sensitive requests are validated before action is taken.""",
                "category": "Security Process",
                "risk": "Low",
                "vector": "Identity Verification"
            },

            12: {
                "title": "3.2.2 Security Awareness",
                "content": """Employee awareness training reduces susceptibility to social engineering attacks.""",
                "category": "Awareness Training",
                "risk": "Low",
                "vector": "User Education"
            },

            13: {
                "title": "3.2.3 Reporting Suspicious Activity",
                "content": """Rapid reporting allows security teams to investigate and contain social engineering attempts.""",
                "category": "Incident Reporting",
                "risk": "Low",
                "vector": "Threat Escalation"
            },

            14: {
                "title": "3.2.4 Organizational Policies",
                "content": """Strong security policies reduce opportunities for manipulation and unauthorized access.""",
                "category": "Governance",
                "risk": "Low",
                "vector": "Policy Enforcement"
            },

            15: {
                "title": "3.2.5 Human Firewall",
                "content": """A well-trained workforce serves as the first line of defense against social engineering attacks.""",
                "category": "Human Defense",
                "risk": "Medium",
                "vector": "Employee Vigilance"
            }

        }

    }

}
},

4: {
"title": "AI Threat Intelligence",

"sections": {

    "4.0 AI Fundamentals": {

        "chapters": {

            1: {
                "title": "4.0.1 Artificial Intelligence",
                "content": """Artificial Intelligence enables systems to perform tasks that normally require human intelligence and decision making.""",
                "category": "AI Fundamentals",
                "risk": "Low",
                "vector": "Machine Intelligence"
            },

            2: {
                "title": "4.0.2 Machine Learning",
                "content": """Machine learning algorithms learn patterns from data to improve threat detection and analysis.""",
                "category": "Machine Learning",
                "risk": "Medium",
                "vector": "Pattern Recognition"
            },

            3: {
                "title": "4.0.3 Cybersecurity Applications",
                "content": """AI technologies are widely used in phishing detection, malware analysis, and threat intelligence.""",
                "category": "Cyber AI",
                "risk": "Medium",
                "vector": "Automated Detection"
            },

            4: {
                "title": "4.0.4 Threat Scoring",
                "content": """Threat scoring systems prioritize risks based on severity, confidence, and potential impact.""",
                "category": "Threat Assessment",
                "risk": "Medium",
                "vector": "Risk Modeling"
            },

            5: {
                "title": "4.0.5 Predictive Analysis",
                "content": """Predictive models anticipate potential cyber threats before significant damage occurs.""",
                "category": "Predictive Intelligence",
                "risk": "Medium",
                "vector": "Forecasting"
            }

        }

    },

    "4.1 Behavioral Intelligence": {

        "chapters": {

            6: {
                "title": "4.1.1 User Behavior Analysis",
                "content": """Behavioral analytics identify abnormal activities that may indicate compromise.""",
                "category": "Behavior Analytics",
                "risk": "High",
                "vector": "User Monitoring"
            },

            7: {
                "title": "4.1.2 Login Pattern Detection",
                "content": """AI detects unusual authentication activities across enterprise systems.""",
                "category": "Authentication Intelligence",
                "risk": "High",
                "vector": "Access Monitoring"
            },

            8: {
                "title": "4.1.3 Phishing Pattern Recognition",
                "content": """Machine learning identifies phishing characteristics from large datasets.""",
                "category": "Threat Recognition",
                "risk": "High",
                "vector": "Pattern Detection"
            },

            9: {
                "title": "4.1.4 Threat Classification",
                "content": """AI classifies threats according to behavior, severity, and attack characteristics.""",
                "category": "Threat Intelligence",
                "risk": "Medium",
                "vector": "Automated Classification"
            },

            10: {
                "title": "4.1.5 Anomaly Detection",
                "content": """Anomaly detection identifies deviations from expected behavior that may indicate attacks.""",
                "category": "Behavior Monitoring",
                "risk": "High",
                "vector": "Anomaly Analysis"
            }

        }

    },

    "4.2 Enterprise AI Defense": {

        "chapters": {

            11: {
                "title": "4.2.1 Security Automation",
                "content": """Automation accelerates threat detection and incident response processes.""",
                "category": "Automation",
                "risk": "Low",
                "vector": "Security Orchestration"
            },

            12: {
                "title": "4.2.2 Incident Response AI",
                "content": """AI assists analysts by prioritizing alerts and recommending actions.""",
                "category": "Incident Response",
                "risk": "Medium",
                "vector": "Decision Support"
            },

            13: {
                "title": "4.2.3 Threat Intelligence Platforms",
                "content": """Threat intelligence platforms aggregate and analyze cybersecurity data from multiple sources.""",
                "category": "Threat Intelligence",
                "risk": "Medium",
                "vector": "Data Aggregation"
            },

            14: {
                "title": "4.2.4 AI Limitations",
                "content": """Understanding AI limitations is essential for responsible cybersecurity deployment.""",
                "category": "Risk Management",
                "risk": "Low",
                "vector": "Technology Governance"
            },

            15: {
                "title": "4.2.5 Future of Cyber Defense",
                "content": """Future cyber defense strategies will increasingly combine human expertise with artificial intelligence.""",
                "category": "Emerging Technology",
                "risk": "Medium",
                "vector": "Future Intelligence"
            }

        }

    }

}
},
}


# =========================================
# MODULE PAGE
# =========================================

@app.route("/module/<int:module_id>/chapter/<int:chapter_id>")
@login_required
def module(module_id, chapter_id):

    module_data = academy_modules.get(module_id)

    if not module_data:
        return redirect("/academy")

    chapter_data = None

    # Module 1 (sections structure)
    if "sections" in module_data:

        for section in module_data["sections"].values():

            if chapter_id in section["chapters"]:

                chapter_data = section["chapters"][chapter_id]
                break

        total_chapters = sum(
            len(section["chapters"])
            for section in module_data["sections"].values()
        )

    # Module 2, 3, 4 (chapters structure)
    else:

        chapter_data = module_data["chapters"].get(chapter_id)

        total_chapters = len(
            module_data["chapters"]
        )

    if not chapter_data:
        return redirect("/academy")

    progress = int(
        (chapter_id / total_chapters) * 100
    )

    previous_chapter = chapter_id - 1
    next_chapter = chapter_id + 1

    is_completed = False

    if chapter_id == total_chapters:

        is_completed = True

        completed_modules = session.get(
            "completed_modules",
            []
        )

        if module_id not in completed_modules:

            completed_modules.append(module_id)

            session["completed_modules"] = completed_modules

    return render_template(

        "module.html",

        module_id=module_id,
        chapter_id=chapter_id,

        module_data=module_data,

        module_title=module_data["title"],

        chapter_title=chapter_data["title"],

        chapter_content=chapter_data.get(
            "content",
            ""
        ),

        category=chapter_data.get(
            "category",
            "Cyber Threat"
        ),

        risk=chapter_data.get(
            "risk",
            "Medium"
        ),

        vector=chapter_data.get(
            "vector",
            "Email Based"
        ),

        sections=module_data.get(
            "sections",
            {}
        ),

        chapters=module_data.get(
            "chapters",
            {}
        ),

        total_chapters=total_chapters,
        progress=progress,

        previous_chapter=previous_chapter,
        next_chapter=next_chapter,

        is_completed=is_completed

    )

# =========================================
# SIMULATOR
# =========================================

@app.route("/simulator", methods=["GET", "POST"])
@login_required
def simulator():

    scenario = None
    metadata = None

    threat_category = ""
    simulation_format = ""

    fake_link = "https://secure-verification-center.com/login"

    if request.method == "POST":

        threat_category = request.form.get("threat_category")
        simulation_format = request.form.get("simulation_format")
        risk_level = request.form.get("risk_level")

        metadata = {
            "threat_category": threat_category,
            "simulation_format": simulation_format,
            "risk_level": risk_level
}

        if threat_category == "Credential Phishing":

            if risk_level == "Safe":

                scenario = """
        Subject: Team Meeting Reminder

        Dear Employee,

        A project meeting has been scheduled
        for Monday at 10:00 AM.

        Please review the meeting agenda
        before attending.

        Thank you.

        Human Resources Department
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Contact Information Review

        Dear Employee,

        We are conducting a routine review
        of employee records.

        Please confirm that your contact
        information remains accurate.

        Thank you.

        Administration Department
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Customer Information Update

        Dear Customer,

        As part of our annual records review,
        we are updating customer information.

        Please review your profile details
        and submit any necessary updates
        within the next 14 days.

        Thank you.

        Customer Relations Team
        """

            elif risk_level == "High":

                scenario = """
        Subject: Security Alert

        Dear User,

        Suspicious login attempts have been
        detected on your account.

        To prevent unauthorized access,
        please verify your account details
        within 24 hours.

        Failure to complete verification
        may result in temporary account
        suspension.

        Security Operations Center
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Immediate Action Required

        Dear User,

        Multiple unauthorized login attempts
        have been detected on your account.

        Your account has been temporarily
        suspended for security reasons.

        Click the verification link below
        immediately to restore access.

        Failure to verify within 2 hours
        may result in permanent account
        deactivation.

        Security Response Team
        """
                
        elif threat_category == "Banking Fraud":

            if risk_level == "Safe":

                scenario = """
        Subject: Transaction Confirmation

        Dear Customer,

        Your recent transfer of RM 150.00
        has been successfully processed.

        If you recognize this transaction,
        no further action is required.

        Thank you for banking with us.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Account Verification Needed

        Dear Customer,

        We noticed an issue with your bank
        account information.

        Please verify your details to avoid
        temporary service interruptions.

        Thank you.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Unusual Banking Activity

        We detected unusual activity on your
        bank account.

        To ensure account security, please
        confirm your account information
        within 48 hours.

        Failure to verify may result in
        temporary account restrictions.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Immediate Banking Verification

        Dear Valued Customer,

        Multiple login attempts have been
        detected on your online banking account.

        To protect your funds, please complete
        the verification process immediately.

        Failure to respond within 24 hours may
        result in account suspension.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Urgent Fraud Prevention Notice

        Dear Customer,

        Our fraud monitoring system has
        identified potentially unauthorized
        transactions totaling RM 12,850.00.

        Immediate verification is required to
        prevent permanent account restrictions
        and financial losses.

        Failure to verify within 2 hours may
        result in account lockdown and delayed
        fund recovery procedures.

        Bank Security Operations Center
        """
        elif threat_category == "Social Engineering":

            if risk_level == "Safe":

                scenario = """
        Subject: Employee Awareness Program

        Dear Team,

        The monthly cybersecurity awareness
        training will be conducted next week.

        Please complete the training module
        before Friday.

        Thank you.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Survey Invitation

        Hello,

        You have been selected to participate
        in a company feedback survey.

        Please complete the survey at your
        earliest convenience.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Account Confirmation Required

        We are updating employee records.

        Please verify your contact details
        to ensure uninterrupted access to
        company services.
        """

            elif risk_level == "High":

                scenario = """
        Subject: HR Department Notice

        Your employee benefits profile requires
        immediate review.

        Failure to confirm your information
        within 24 hours may affect payroll
        processing.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Internal Investigation Notice

        A compliance review has identified
        potential irregularities associated
        with your employee account.

        Immediate verification is required.

        Failure to cooperate may result in
        temporary suspension of access.
        """
        elif threat_category == "Malware Delivery":

            if risk_level == "Safe":

                scenario = """
        Subject: Monthly Report Attached

        Please find the approved monthly
        performance report attached.

        Thank you.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Important Document

        Please review the attached document
        and provide your feedback.

        Regards.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Updated Company Policy

        A revised policy document has been
        issued.

        Open the attachment to review the
        latest changes.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Secure Invoice Attached

        An invoice requires immediate review.

        Open the attachment and confirm the
        payment details before processing.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Security Patch Deployment

        Critical system updates have been
        released.

        Download and execute the attached
        installer immediately to prevent
        service disruptions.

        Failure to update may expose systems
        to severe vulnerabilities.
        """
        elif threat_category == "Crypto Scam":

            if risk_level == "Safe":

                scenario = """
        Subject: Cryptocurrency Portfolio Update

        Your portfolio summary is now available.

        Review your latest account performance
        through the official platform.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Limited-Time Crypto Reward

        Congratulations.

        You have been selected to receive
        a promotional cryptocurrency reward.

        Claim today.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Wallet Verification Required

        Your cryptocurrency wallet requires
        identity verification.

        Complete verification within 48 hours
        to avoid restrictions.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Urgent Wallet Security Alert

        Suspicious activity has been detected
        on your wallet.

        Verify ownership immediately to
        protect your digital assets.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Asset Recovery Program

        Our blockchain monitoring system has
        identified compromised assets linked
        to your wallet.

        Transfer all holdings to the recovery
        wallet immediately to prevent loss.

        Failure to act may result in permanent
        asset forfeiture.
        """
        elif threat_category == "Crypto Scam":

            if risk_level == "Safe":

                scenario = """
        Subject: Cryptocurrency Portfolio Update

        Your portfolio summary is now available.

        Review your latest account performance
        through the official platform.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Limited-Time Crypto Reward

        Congratulations.

        You have been selected to receive
        a promotional cryptocurrency reward.

        Claim today.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Wallet Verification Required

        Your cryptocurrency wallet requires
        identity verification.

        Complete verification within 48 hours
        to avoid restrictions.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Urgent Wallet Security Alert

        Suspicious activity has been detected
        on your wallet.

        Verify ownership immediately to
        protect your digital assets.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Asset Recovery Program

        Our blockchain monitoring system has
        identified compromised assets linked
        to your wallet.

        Transfer all holdings to the recovery
        wallet immediately to prevent loss.

        Failure to act may result in permanent
        asset forfeiture.
        """
        elif threat_category == "Executive Impersonation":

            if risk_level == "Safe":

                scenario = """
        Subject: Leadership Meeting Reminder

        Dear Team,

        A leadership strategy meeting has been
        scheduled for next Monday at 10:00 AM.

        Please prepare the required reports.

        Regards,
        CEO Office
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Quick Assistance Needed

        Hello,

        I need a quick update regarding our
        current project status.

        Please respond when available.

        CEO
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Urgent Request From Management

        I am currently traveling and unable
        to access company systems.

        Please assist with a time-sensitive
        task and respond immediately.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Confidential Executive Request

        I need you to handle a confidential
        business matter immediately.

        Do not discuss this request with
        other employees until completed.

        CEO Office
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Executive Financial Directive

        A strategic acquisition requires an
        immediate confidential transfer.

        This request must be completed before
        the end of business today.

        Do not delay or disclose details.

        Chief Executive Officer
        """
        elif threat_category == "Cloud Service Spoofing":

            if risk_level == "Safe":

                scenario = """
        Subject: Microsoft 365 Activity Report

        Your weekly Microsoft 365 usage report
        is now available.

        Thank you for using our services.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Storage Capacity Warning

        Your cloud storage is approaching
        its capacity limit.

        Review your storage usage.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: OneDrive Synchronization Issue

        We detected synchronization issues
        within your cloud account.

        Please review your account settings.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Microsoft 365 Security Alert

        Suspicious activity has been detected
        within your Microsoft 365 environment.

        Immediate verification is recommended.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Cloud Access Suspension Notice

        Your Microsoft 365 access will be
        restricted due to security concerns.

        Immediate verification is required
        to prevent account lockout.

        Cloud Security Operations
        """
        elif threat_category == "Fake Invoice Scam":

            if risk_level == "Safe":

                scenario = """
        Subject: Invoice Payment Confirmation

        Payment for Invoice INV-2026-1542
        has been successfully received.

        Thank you for your business.
        """

        elif risk_level == "Low":

                scenario = """
        Subject: Outstanding Invoice Reminder

        This is a reminder regarding a pending
        invoice requiring review.

        Thank you.
        """

        elif risk_level == "Medium":

                scenario = """
        Subject: Invoice Due Notice

        An invoice remains unpaid and requires
        attention.

        Please review payment details.
        """

        elif risk_level == "High":

                scenario = """
        Subject: Immediate Invoice Settlement

        A supplier invoice is overdue and
        requires urgent settlement.

        Failure to process payment may result
        in service disruption.
        """

        elif risk_level == "Critical":

                scenario = """
        Subject: Final Payment Demand

        Invoice INV-88921 remains unpaid.

        Failure to process payment within
        24 hours may result in legal action
        and suspension of services.

        Accounts Department
        """
        elif threat_category == "Payment Redirection Fraud":

            if risk_level == "Safe":

                scenario = """
        Subject: Banking Information Update

        Our supplier banking details remain
        unchanged.

        No action is required.

        Thank you.
        """

            elif risk_level == "Low":

                scenario = """
        Subject: Vendor Account Update

        Please note minor updates to supplier
        contact information.

        Regards.
        """

            elif risk_level == "Medium":

                scenario = """
        Subject: Payment Processing Change

        Future payments should be reviewed
        using the latest supplier details.

        Thank you.
        """

            elif risk_level == "High":

                scenario = """
        Subject: Urgent Banking Detail Update

        Please update our banking details
        before processing the next payment.

        Failure to do so may delay orders.
        """

            elif risk_level == "Critical":

                scenario = """
        Subject: Immediate Payment Redirection

        Due to banking maintenance, all future
        payments must be redirected to the
        new account provided.

        This change is effective immediately.

        Finance Department
        """
    # =========================================
    # THREAT CATEGORY LINK
    # =========================================

    fake_link = "https://secure-verification-center.com/login"

    if threat_category == "Credential Phishing":

        fake_link = "https://microsoft-security-login.com"

    elif threat_category == "Banking Fraud":

        fake_link = "https://maybank-secure-verification.com"

    elif threat_category == "Social Engineering":

        fake_link = "https://employee-records-update.com"

    elif threat_category == "Business Email Compromise":

        fake_link = "https://finance-transfer-review.com"

    elif threat_category == "Crypto Scam":

        fake_link = "https://crypto-wallet-verification.com"

    elif threat_category == "Malware Delivery":

        fake_link = "https://security-update-download.com"

    elif threat_category == "Executive Impersonation":

         fake_link = "https://ceo-priority-request.com"

    elif threat_category == "Cloud Service Spoofing":

        fake_link = "https://onedrive-security-center.com"

    elif threat_category == "Fake Invoice Scam":

        fake_link = "https://invoice-payment-review.com"

    elif threat_category == "Payment Redirection Fraud":

        fake_link = "https://supplier-banking-update.com"


    # =========================================
    # SIMULATION FORMAT
    # =========================================

    if scenario:

        if simulation_format == "Email / Message Content + Link":

            scenario += f"""

    Link:
    {fake_link}
    """

        elif simulation_format == "Link Only":

            scenario = fake_link

    return render_template(
        "simulator.html",
        scenario=scenario,
        metadata=metadata
    )
# =========================================
# HELP CENTER
# =========================================

@app.route("/help")
@login_required
def help_center():

    return render_template("help.html")
# =========================================
# SUPPORT REQUEST
# =========================================

@app.route("/support-request", methods=["GET", "POST"])
@login_required
def support_request():

    message = None

    if request.method == "POST":

        name = request.form.get("name")
        email = request.form.get("email")
        category = request.form.get("category")
        support_message = request.form.get("message")

        db = get_db()
        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO support_requests (

                username,
                name,
                email,
                category,
                message,
                status,
                created_at

            )

            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["user"],
                name,
                email,
                category,
                support_message,
                "Open",
                datetime.now().strftime(
                    "%d %B %Y %H:%M"
                )
            )
        )

        db.commit()
        db.close()

        message = (
            "Support request submitted successfully."
        )

    return render_template(
        "support_request.html",
        message=message
    )
# =========================================
# SUPPORT HISTORY
# =========================================

@app.route("/support-history")
@login_required
def support_history():

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        SELECT *
        FROM support_requests
        WHERE username=?
        ORDER BY id DESC
        """,
        (session["user"],)
    )

    tickets = cursor.fetchall()

    db.close()

    return render_template(
        "support_history.html",
        tickets=tickets
    )

# =========================================
# ABOUT PLATFORM
# =========================================

@app.route("/about")
@login_required
def about():

    return render_template("about.html")

# =========================================
# EXPORT PDF
# =========================================

@app.route("/export_pdf")
@login_required
def export_pdf():

    global latest_report

    if not latest_report:

        return redirect("/home")

    buffer = BytesIO()

    doc = SimpleDocTemplate(

        buffer,
        pagesize=letter

    )

    styles = getSampleStyleSheet()

    story = []

    story.append(

        Paragraph(

            "<b>MAILORA THREAT REPORT</b>",
            styles["Title"]

        )

    )

    story.append(Spacer(1, 20))

    content = f"""

    <b>Email Content:</b><br/>
    {latest_report['email_content']}<br/><br/>

    <b>URL:</b><br/>
    {latest_report['url']}<br/><br/>

    <b>Threat Score:</b><br/>
    {latest_report['score']}<br/><br/>

    <b>Classification:</b><br/>
    {latest_report['result']}<br/><br/>

    <b>Generated:</b><br/>
    {latest_report['timestamp']}<br/><br/>

    """

    story.append(

        Paragraph(

            content,
            styles["BodyText"]

        )

    )

    doc.build(story)

    buffer.seek(0)

    return send_file(

        buffer,

        as_attachment=True,

        download_name="mailora_report.pdf",

        mimetype="application/pdf"

    )

# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

# =========================================
# RUN APP
# =========================================

if __name__ == "__main__":

    app.run(debug=True)