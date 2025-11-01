from flask import Flask, render_template, request
import pickle
import pandas as pd
from utils.feature_extractor import extract_url_features
import os
from urllib.parse import urlparse

app = Flask(__name__)

# Load trained model with error handling
try:
    model_path = 'model/phishing_xgb_model.pkl'
    if os.path.exists(model_path):
        model = pickle.load(open(model_path, 'rb'))
        print("✅ Model loaded successfully")
        print(f"✅ Model expects {model.n_features_in_} features")
    else:
        print("❌ Model file not found. Please train the model first.")
        model = None
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None

def is_likely_legitimate(url):
    """Rule-based check for legitimate websites"""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        
        # Known legitimate domains
        legit_domains = ['google.com', 'github.com', 'microsoft.com', 'apple.com',
                        'facebook.com', 'amazon.com', 'paypal.com', 'netflix.com',
                        'youtube.com', 'twitter.com', 'instagram.com', 'linkedin.com']
        
        for domain in legit_domains:
            if netloc == domain or netloc.endswith('.' + domain):
                return True
        
        # Rule-based checks
        if parsed.scheme == 'https' and len(netloc) < 20 and netloc.count('-') == 0:
            return True
            
        return False
    except:
        return False

def is_likely_phishing(url):
    """Rule-based check for phishing websites"""
    url_lower = url.lower()
    
    # Clear phishing indicators
    phishing_terms = ['verify-', 'login-', 'secure-', 'account-', 'update-', 
                     'banking-', 'password-', 'confirm-', 'validation-']
    
    if any(term in url_lower for term in phishing_terms):
        return True
    
    # Suspicious patterns
    if url.count('-') > 3 or url.count('.') > 4 or len(url) > 60:
        return True
        
    return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url'].strip()
        
        if not url:
            return render_template('result.html', 
                                 url="No URL provided", 
                                 result="❌ Please enter a URL",
                                 error=True)
        
        # Rule-based classification first
        if is_likely_legitimate(url):
            return render_template('result.html', 
                                 url=url, 
                                 result="✅ Legitimate Website",
                                 confidence="99%",
                                 error=False)
        
        if is_likely_phishing(url):
            return render_template('result.html', 
                                 url=url, 
                                 result="⚠️ Phishing Website", 
                                 confidence="95%",
                                 error=False)
        
        # ML model as fallback
        if model is None:
            return render_template('result.html',
                                 url=url,
                                 result="❌ Model not available",
                                 error=True)
        
        try:
            features = extract_url_features(url)
            prediction = model.predict(features)[0]
            probability = model.predict_proba(features)[0]
            
            confidence = probability[1] if prediction == 1 else probability[0]
            result = "⚠️ Phishing Website" if prediction == 1 else "✅ Legitimate Website"

            return render_template('result.html', 
                                 url=url, 
                                 result=result,
                                 confidence=f"{confidence:.2%}",
                                 error=False)
            
        except Exception as e:
            return render_template('result.html',
                                 url=url,
                                 result=f"❌ Error: {str(e)}",
                                 error=True)

if __name__ == '__main__':
    app.run(debug=True)