# import pandas as pd
# import re
# from urllib.parse import urlparse
# import numpy as np
# from collections import Counter

# def extract_url_features(url):
#     """
#     Extract features from URL for phishing detection.
    
#     Args:
#         url (str): URL to analyze.
#     Returns:
#         pd.DataFrame: Feature vector for model prediction.
#     """
#     features = {}

#     try:
#         # Parse URL
#         parsed = urlparse(url)
#         domain = parsed.netloc
#         path = parsed.path

#         # Basic URL features
#         features['url_length'] = len(url)
#         features['domain_length'] = len(domain)
#         features['path_length'] = len(path)

#         # Character counts
#         chars = ['.', '-', '_', '/', '?', '=', '@', '&', '!', ' ', '~', ',', '+', '*', '#', '$', '%']
#         for c in chars:
#             features[f'num_{repr(c)[1:-1].replace("/", "slashes")}'] = url.count(c)

#         # Digits and letters
#         features['num_digits'] = sum(c.isdigit() for c in url)
#         features['num_letters'] = sum(c.isalpha() for c in url)

#         # HTTPS check
#         features['https'] = 1 if parsed.scheme == 'https' else 0

#         # IP address check
#         features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0

#         # Suspicious keywords
#         suspicious_words = [
#             'verify', 'account', 'update', 'secure', 'banking', 
#             'confirm', 'login', 'signin', 'ebayisapi', 'webscr',
#             'password', 'suspend', 'alert', 'authenticate'
#         ]
#         features['has_suspicious_words'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

#         # Domain features
#         domain_parts = domain.split('.')
#         features['subdomain_count'] = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
#         features['domain_has_digits'] = 1 if any(c.isdigit() for c in domain) else 0
#         features['tld_length'] = len(domain_parts[-1]) if domain_parts else 0

#         # Path suspiciousness
#         features['path_has_suspicious'] = 1 if any(word in path.lower() for word in
#             ['login', 'signin', 'account', 'verify', 'update', 'confirm']) else 0

#         # Entropy (randomness measure)
#         if len(url) > 0:
#             counter = Counter(url)
#             entropy = -sum((count / len(url)) * np.log2(count / len(url)) for count in counter.values())
#             features['entropy'] = entropy
#         else:
#             features['entropy'] = 0

#         # Consonant-vowel ratio
#         vowels = 'aeiouAEIOU'
#         num_vowels = sum(1 for c in url if c in vowels)
#         num_consonants = sum(1 for c in url if c.isalpha() and c not in vowels)
#         features['consonant_vowel_ratio'] = num_consonants / (num_vowels + 1)

#         # Domain hyphens and underscores
#         features['domain_hyphens'] = domain.count('-')
#         features['domain_underscores'] = domain.count('_')

#         # Common legitimate domain check
#         legit_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'github']
#         features['is_common_domain'] = 1 if any(ld in domain.lower() for ld in legit_domains) else 0

#     except Exception as e:
#         print(f"Error extracting features: {e}")
#         # Fallback default feature vector (zeros)
#         features = {f'feature_{i}': 0 for i in range(35)}

#     return pd.DataFrame([features])
import re
import pandas as pd
from urllib.parse import urlparse
import tldextract

def extract_url_features(url):
    """
    Extract only critical features without any domain-based overrides
    """
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    
    # Calculate features without any domain-based overrides
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