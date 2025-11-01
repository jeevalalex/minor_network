
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier
import pickle
import os

# Load dataset
df = pd.read_csv('dataset/dataset_phishing.csv')

print("Dataset shape:", df.shape)
print("Target distribution before encoding:")
print(df['status'].value_counts())

# Encode target labels (phishing=1, legitimate=0)
df['status'] = LabelEncoder().fit_transform(df['status'])
print("\nTarget distribution after encoding:")
print(df['status'].value_counts())

# Select only essential features (top 10 based on importance)
essential_features = [
    'length_url',              # URL length
    'length_hostname',         # Hostname length  
    'nb_dots',                 # Number of dots
    'nb_hyphens',              # Number of hyphens
    'nb_slash',                # Number of slashes
    'https_token',             # HTTPS usage
    'nb_subdomains',           # Number of subdomains
    'prefix_suffix',           # Hyphens in domain (prefix-suffix)
    'phish_hints',             # Phishing keywords
    'suspecious_tld',          # Suspicious TLDs
]

# Check which features exist in dataset
available_features = [f for f in essential_features if f in df.columns]
print(f"Available essential features: {len(available_features)}")
print("Features:", available_features)

# Use essential features
X = df[available_features]
y = df['status']

print(f"Training with {X.shape[1]} essential features")

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train model with better parameters
model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=4,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_alpha=1.0,
    reg_lambda=1.0,
    eval_metric='logloss',
    random_state=42
)

print("\nTraining model...")
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Feature importance
importance_df = pd.DataFrame({
    'feature': available_features,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\n📊 Feature Importance:")
print(importance_df)

# Save model
os.makedirs("model", exist_ok=True)
pickle.dump(model, open("model/phishing_xgb_model.pkl", "wb"))
print("✅ Model saved as phishing_xgb_model.pkl")