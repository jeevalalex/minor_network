# train_model.py (Updated to include network features and save test data)
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score, confusion_matrix
from xgboost import XGBClassifier
import pickle
import os
import matplotlib.pyplot as plt
import numpy as np

# Load dataset
df = pd.read_csv('dataset/dataset_phishing.csv')

print("Dataset shape:", df.shape)
print("Target distribution before encoding:")
print(df['status'].value_counts())

# Encode target labels (phishing=1, legitimate=0)
df['status'] = LabelEncoder().fit_transform(df['status'])
print("\nTarget distribution after encoding:")
print(df['status'].value_counts())

# Select essential features + add network feature placeholders
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
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"\n🎯 Accuracy: {accuracy:.4f}")
print(f"📊 Precision: {precision:.4f}")
print(f"📈 Recall: {recall:.4f}")
print(f"⚡ F1-Score: {f1:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Create and display confusion matrix
cm = confusion_matrix(y_test, y_pred)
print("\n🔄 Confusion Matrix:")
print(cm)

# Plot confusion matrix
plt.figure(figsize=(8, 6))
plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
plt.title('Confusion Matrix')
plt.colorbar()
tick_marks = np.arange(2)
plt.xticks(tick_marks, ['Legitimate', 'Phishing'])
plt.yticks(tick_marks, ['Legitimate', 'Phishing'])
plt.xlabel('Predicted Label')
plt.ylabel('True Label')

# Add text annotations
thresh = cm.max() / 2.
for i in range(cm.shape[0]):
    for j in range(cm.shape[1]):
        plt.text(j, i, format(cm[i, j], 'd'),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black")

plt.tight_layout()
plt.savefig('model/confusion_matrix.png', dpi=100, bbox_inches='tight')
print("✅ Confusion matrix saved as confusion_matrix.png")

# Feature importance
importance_df = pd.DataFrame({
    'feature': available_features,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\n📊 Feature Importance:")
print(importance_df)

# Save model and test data for metrics calculation
os.makedirs("model", exist_ok=True)
pickle.dump(model, open("model/phishing_xgb_model.pkl", "wb"))

# Save test data for metrics calculation in the web app
test_data = {
    'X_test': X_test,
    'y_test': y_test
}
pickle.dump(test_data, open("model/test_data.pkl", "wb"))

print("✅ Model saved as phishing_xgb_model.pkl")
print("✅ Test data saved for metrics calculation")

# Print comprehensive metrics summary
print("\n" + "="*50)
print("📈 COMPREHENSIVE MODEL PERFORMANCE SUMMARY")
print("="*50)
print(f"🎯 Accuracy:    {accuracy:.4f} ({accuracy:.2%})")
print(f"📊 Precision:   {precision:.4f} ({precision:.2%})")
print(f"📈 Recall:      {recall:.4f} ({recall:.2%})")
print(f"⚡ F1-Score:    {f1:.4f} ({f1:.2%})")
print(f"🔢 Test Samples: {len(y_test)}")
print("="*50)