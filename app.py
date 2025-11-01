# app.py
from flask import Flask, render_template, request, jsonify
import pickle
import pandas as pd
from utils.feature_extractor import extract_enhanced_features, extract_basic_features
import os
from urllib.parse import urlparse
import time

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

def analyze_network_indicators(features):
    """Analyze network features for additional insights"""
    indicators = []
    
    # Network latency analysis
    dns_time = features.get('dns_resolution_time', 5)
    if dns_time > 2:
        indicators.append(f"Slow DNS resolution ({dns_time:.2f}s - potentially suspicious)")
    else:
        indicators.append(f"Fast DNS resolution ({dns_time:.2f}s - good sign)")
    
    tcp_time = features.get('tcp_connect_time', 5)
    if tcp_time > 2:
        indicators.append(f"Slow TCP connection ({tcp_time:.2f}s - potentially suspicious)")
    else:
        indicators.append(f"Fast TCP connection ({tcp_time:.2f}s - good sign)")
    
    # Security analysis
    if features.get('is_private_ip', 0) == 1:
        indicators.append("Private IP address (highly suspicious)")
    else:
        indicators.append("Public IP address (normal)")
    
    if features.get('uses_https', 0) == 0:
        indicators.append("No HTTPS encryption (suspicious)")
    else:
        indicators.append("HTTPS encryption present (good sign)")
    
    # Domain reputation
    if features.get('is_new_domain', 1) == 1:
        indicators.append("New domain (potentially suspicious)")
    else:
        domain_age = features.get('domain_age_days', 0)
        indicators.append(f"Established domain ({domain_age} days - good sign)")
    
    if features.get('has_mx_record', 0) == 1:
        indicators.append("MX record present (typical for legitimate sites)")
    else:
        indicators.append("No MX record (suspicious for legitimate sites)")
    
    return indicators

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
        
        print(f"🔍 Analyzing URL: {url}")
        
        # ML model prediction
        if model is None:
            return render_template('result.html',
                                 url=url,
                                 result="❌ Model not available",
                                 error=True)
        
        try:
            start_time = time.time()
            
            # Try to extract enhanced features first
            try:
                features_data = extract_enhanced_features(url)
                model_features_df = features_data['model_features']
                all_features_df = features_data['all_features']
                feature_vector = all_features_df.iloc[0]
                using_enhanced_features = True
            except Exception as e:
                print(f"⚠️ Enhanced features failed, using basic features: {e}")
                model_features_df = extract_basic_features(url)
                feature_vector = model_features_df.iloc[0]
                using_enhanced_features = False
            
            # Make prediction using ONLY the 10 original features
            prediction = model.predict(model_features_df)[0]
            probability = model.predict_proba(model_features_df)[0]
            
            confidence = probability[1] if prediction == 1 else probability[0]
            result = "⚠️ Phishing Website" if prediction == 1 else "✅ Legitimate Website"
            
            # Network analysis (only if enhanced features worked)
            if using_enhanced_features:
                network_indicators = analyze_network_indicators(feature_vector)
                features_used = len(model_features_df.columns)
                total_features_analyzed = len(feature_vector)
            else:
                network_indicators = ["Basic URL analysis only - Network features unavailable"]
                features_used = len(model_features_df.columns)
                total_features_analyzed = features_used
            
            processing_time = time.time() - start_time
            
            return render_template('network_result.html', 
                                 url=url, 
                                 result=result,
                                 confidence=f"{confidence:.2%}",
                                 processing_time=f"{processing_time:.2f}s",
                                 network_indicators=network_indicators,
                                 features_used=features_used,
                                 total_features_analyzed=total_features_analyzed,
                                 error=False)
            
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return render_template('result.html',
                                 url=url,
                                 result=f"❌ Error analyzing URL: {str(e)}",
                                 error=True)

@app.route('/network/info')
def network_info():
    """Endpoint to show network information"""
    return jsonify({
        "message": "Network-oriented phishing detection system",
        "features": [
            "DNS analysis",
            "Network latency measurement", 
            "WHOIS domain information",
            "SSL/TLS verification",
            "IP reputation checking"
        ],
        "model_features": 10,
        "network_features": 14,
        "status": "active"
    })

if __name__ == '__main__':
    print("🌐 Starting Network-Oriented Phishing Detection System...")
    print("📡 Network features: DNS analysis, Latency measurement, WHOIS lookup")
    print("🤖 Using 10-feature ML model + 14 network features for analysis")
    app.run(debug=True, host='0.0.0.0', port=5000)