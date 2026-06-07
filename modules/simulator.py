import random

# =========================================
# SAFE EMAILS
# =========================================

safe_templates = {

    "bank": [

        """
        SUBJECT: Monthly Banking Statement Available

        Dear Customer,

        Your monthly banking statement is now available
        through the official banking mobile application.

        No action is required.

        Thank you,
        Trusted National Bank
        """

    ],

    "delivery": [

        """
        SUBJECT: Delivery Successfully Scheduled

        Your parcel delivery has been confirmed.

        Estimated arrival:
        Tomorrow before 5 PM.

        Thank you for choosing our service.
        """

    ],

    "password": [

        """
        SUBJECT: Password Successfully Updated

        Your enterprise account password was updated successfully.

        If this was not performed by you,
        please contact your administrator immediately.

        IT Security Team
        """

    ]
}

# =========================================
# SUSPICIOUS EMAILS
# =========================================

suspicious_templates = {

    "bank": [

        """
        SUBJECT: Account Verification Reminder

        Dear Customer,

        We noticed unusual login activity
        on your online banking profile.

        Please review your account activity soon.

        Banking Security Team
        """

    ],

    "delivery": [

        """
        SUBJECT: Delivery Address Confirmation

        Your package may experience delays
        due to incomplete shipping details.

        Please verify your information.

        Shipping Department
        """

    ],

    "password": [

        """
        SUBJECT: Password Expiration Reminder

        Your password will expire in 3 days.

        Please consider updating it
        through your internal company portal.

        IT Department
        """

    ]
}

# =========================================
# HIGH RISK EMAILS
# =========================================

high_risk_templates = {

    "bank": [

        """
        URGENT SECURITY NOTICE

        Suspicious financial activity has been detected
        on your banking account.

        Immediate verification is required.

        Verify now:
        http://banking-security-check.net

        Banking Fraud Team
        """

    ],

    "delivery": [

        """
        DELIVERY FAILURE ALERT

        Your package delivery was unsuccessful.

        Update your shipping details immediately:
        http://delivery-confirmation-check.com

        Delivery Operations Team
        """

    ],

    "password": [

        """
        PASSWORD SECURITY WARNING

        Multiple unauthorized login attempts detected.

        Verify your account immediately:
        http://mail-password-reset-alert.net

        Corporate Security Team
        """

    ]
}

# =========================================
# CRITICAL RISK EMAILS
# =========================================

critical_templates = {

    "bank": [

        """
        CRITICAL BANKING ALERT

        Your banking account has been suspended
        due to suspected fraudulent transactions.

        Failure to verify immediately
        may result in permanent account termination.

        Restore access now:
        http://secure-banking-verification-alert.com

        Cyber Fraud Division
        """

    ],

    "delivery": [

        """
        FINAL DELIVERY WARNING

        Your package will be permanently cancelled
        if address verification is not completed now.

        Immediate action required:
        http://urgent-delivery-verification.net

        Global Shipping Center
        """

    ],

    "password": [

        """
        CRITICAL SECURITY BREACH DETECTED

        Your enterprise mailbox credentials
        may have been compromised.

        Immediate password verification required:
        http://enterprise-security-authentication.net

        Failure to respond immediately
        may result in account lockdown.

        Cybersecurity Operations Center
        """

    ]
}

# =========================================
# GENERATE THREAT SIMULATION
# =========================================

def generate_phishing_template(template_type, risk_level):

    # SAFE
    if risk_level == "safe":

        return random.choice(
            safe_templates.get(template_type, [])
        )

    # SUSPICIOUS
    elif risk_level == "suspicious":

        return random.choice(
            suspicious_templates.get(template_type, [])
        )

    # HIGH RISK
    elif risk_level == "high":

        return random.choice(
            high_risk_templates.get(template_type, [])
        )

    # CRITICAL
    elif risk_level == "critical":

        return random.choice(
            critical_templates.get(template_type, [])
        )

    return """

    No threat simulation generated.

    Please select:
    - email type
    - risk level

    """