import pandas as pd

df = pd.read_csv("datasets/phishing_email.csv")

print("\nCOLUMNS:")
print(df.columns.tolist())

print("\nFIRST 5 ROWS:")
print(df.head())