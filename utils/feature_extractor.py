# utils/feature_extractor.py
import re
import pandas as pd
from urllib.parse import urlparse
import tldextract
from utils.network_features import SimpleNetworkFeatureExtractor

def extract_enhanced_features(url):
    """
    Extract both URL-based and network-based features
    Returns a dictionary with both model_features and all_features
    """
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Original URL features (EXACTLY the 10 features the model expects)
    model_features = {
        'length_url': len(url),
        'length_hostname': len(netloc),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_slash': url.count('/'),
        'https_token': 1 if parsed.scheme == 'https' else 0,
        'nb_subdomains': len([s for s in ext.subdomain.split('.') if s]) if ext.subdomain else 0,
        'prefix_suffix': 1 if '-' in netloc else 0,
        'phish_hints': sum(1 for word in ['login', 'verify', 'secure', 'account', 'update', 
                                        'banking', 'password', 'confirm'] if word in url.lower()),
        'suspecious_tld': 1 if ext.suffix in ['.tk', '.ml', '.ga', '.cf', '.gq'] else 0,
    }
    
    # Network features (for display only, not for model prediction)
    try:
        network_extractor = SimpleNetworkFeatureExtractor()
        network_features = network_extractor.extract_network_features(url)
    except Exception as e:
        print(f"⚠️ Network feature extraction failed: {e}")
        network_features = {}
    
    # Combine all features for display
    all_features = {**model_features, **network_features}
    
    print(f"🔍 Extracted {len(model_features)} model features + {len(network_features)} network features")
    
    # Return both dataframes
    return {
        'model_features': pd.DataFrame([model_features]),  # Only the 10 original features
        'all_features': pd.DataFrame([all_features])       # All features for display
    }

# Fallback function in case of issues
def extract_basic_features(url):
    """Extract only the basic 10 features for model prediction"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    netloc = parsed.netloc.lower()
    
    features = {
        'length_url': len(url),
        'length_hostname': len(netloc),
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_slash': url.count('/'),
        'https_token': 1 if parsed.scheme == 'https' else 0,
        'nb_subdomains': len([s for s in ext.subdomain.split('.') if s]) if ext.subdomain else 0,
        'prefix_suffix': 1 if '-' in netloc else 0,
        'phish_hints': sum(1 for word in ['login', 'verify', 'secure', 'account', 'update', 
                                        'banking', 'password', 'confirm'] if word in url.lower()),
        'suspecious_tld': 1 if ext.suffix in ['.tk', '.ml', '.ga', '.cf', '.gq'] else 0,
    }
    
    return pd.DataFrame([features])