import pandas as pd
from modules.analyzer import analyze_email


def evaluate_dataset():

    # =========================
    # LOAD DATASET
    # =========================

    dataset_path = "datasets/phishing_email.csv"

    df = pd.read_csv(dataset_path)

    # =========================
    # RESULTS STORAGE
    # =========================

    total_emails = 0

    phishing_detected = 0

    legitimate_detected = 0

    correct_predictions = 0

    phishing_samples = []

    # =========================
    # LOOP THROUGH DATASET
    # =========================

    for index, row in df.iterrows():

        try:

            email_text = str(row["text_combined"])

            actual_label = int(row["label"])

            # Analyze email using Mailora AI engine
            result = analyze_email(email_text)

            prediction = result["result"]

            total_emails += 1

            # =========================
            # DETECTION LOGIC
            # =========================

            predicted_phishing = prediction in [

                "Suspicious",
                "High Risk",
                "Critical Risk"

            ]

            if predicted_phishing:

                phishing_detected += 1

            else:

                legitimate_detected += 1

            # =========================
            # ACCURACY CHECK
            # =========================

            if actual_label == 1 and predicted_phishing:

                correct_predictions += 1

            elif actual_label == 0 and not predicted_phishing:

                correct_predictions += 1

            # =========================
            # SAVE SAMPLE RESULTS
            # =========================

            if len(phishing_samples) < 5:

                phishing_samples.append({

                    "email": email_text[:200],
                    "prediction": prediction,
                    "actual_label": actual_label

                })

        except:

            continue

    # =========================
    # ACCURACY CALCULATION
    # =========================

    if total_emails > 0:

        accuracy = round(
            (correct_predictions / total_emails) * 100,
            2
        )

    else:

        accuracy = 0

    # =========================
    # RETURN RESULTS
    # =========================

    return {

        "total_emails": total_emails,
        "phishing_detected": phishing_detected,
        "legitimate_detected": legitimate_detected,
        "correct_predictions": correct_predictions,
        "accuracy": accuracy,
        "samples": phishing_samples

    }