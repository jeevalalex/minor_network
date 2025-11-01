# utils/network_features.py
import socket
import time
import whois
from urllib.parse import urlparse
import requests
import dns.resolver
from datetime import datetime

class SimpleNetworkFeatureExtractor:
    def __init__(self):
        self.timeout = 5
    
    def extract_network_features(self, url):
        """Extract network-level features without scapy"""
        features = {}
        
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Basic network features
            features.update(self._get_basic_network_features(domain))
            
            # DNS features
            features.update(self._get_dns_features(domain))
            
            # HTTP features
            features.update(self._get_http_features(url))
            
            # WHOIS features (if available)
            features.update(self._get_whois_features(domain))
            
        except Exception as e:
            print(f"Error extracting network features: {e}")
            # Set default values
            features.update(self._get_default_features())
        
        return features
    
    def _get_basic_network_features(self, domain):
        """Get basic network connectivity features"""
        features = {}
        try:
            # DNS resolution time
            start_time = time.time()
            ip_address = socket.gethostbyname(domain)
            features['dns_resolution_time'] = time.time() - start_time
            
            # Check if IP is private (suspicious)
            if ip_address.startswith(('10.', '172.16.', '192.168.', '169.254.')):
                features['is_private_ip'] = 1
            else:
                features['is_private_ip'] = 0
                
            # TCP connection time
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((domain, 80))
            features['tcp_connect_time'] = time.time() - start_time
            sock.close()
            
        except Exception as e:
            features.update({
                'dns_resolution_time': 5.0,
                'is_private_ip': 0,
                'tcp_connect_time': 5.0
            })
        
        return features
    
    def _get_dns_features(self, domain):
        """Extract DNS-related features"""
        features = {}
        try:
            # Check for common DNS records
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # MX record check (email servers - usually present in legitimate sites)
            try:
                mx_records = resolver.resolve(domain, 'MX')
                features['has_mx_record'] = 1
            except:
                features['has_mx_record'] = 0
            
            # TXT record check
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                features['has_txt_record'] = 1
            except:
                features['has_txt_record'] = 0
                
        except Exception as e:
            features.update({
                'has_mx_record': 0,
                'has_txt_record': 0
            })
        
        return features
    
    def _get_http_features(self, url):
        """Extract HTTP-related features"""
        features = {}
        try:
            # HTTP response time and status
            start_time = time.time()
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            features['http_response_time'] = time.time() - start_time
            features['http_status_code'] = response.status_code
            features['content_length'] = len(response.content)
            
            # Check for HTTPS
            if url.startswith('https://'):
                features['uses_https'] = 1
            else:
                features['uses_https'] = 0
                
        except Exception as e:
            features.update({
                'http_response_time': 5.0,
                'http_status_code': 0,
                'content_length': 0,
                'uses_https': 0
            })
        
        return features
    
    def _get_whois_features(self, domain):
        """Extract WHOIS information"""
        features = {}
        try:
            whois_info = whois.whois(domain)
            
            # Domain age
            if whois_info.creation_date:
                if isinstance(whois_info.creation_date, list):
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                
                domain_age = (datetime.now() - creation_date).days
                features['domain_age_days'] = domain_age
                
                # New domains are more suspicious
                if domain_age < 30:
                    features['is_new_domain'] = 1
                else:
                    features['is_new_domain'] = 0
            else:
                features['domain_age_days'] = 0
                features['is_new_domain'] = 1
                
            # Registrar presence
            features['has_registrar'] = 1 if whois_info.registrar else 0
            
        except Exception as e:
            features.update({
                'domain_age_days': 0,
                'is_new_domain': 1,
                'has_registrar': 0
            })
        
        return features
    
    def _get_default_features(self):
        """Return default feature values when extraction fails"""
        return {
            'dns_resolution_time': 5.0,
            'is_private_ip': 0,
            'tcp_connect_time': 5.0,
            'has_mx_record': 0,
            'has_txt_record': 0,
            'http_response_time': 5.0,
            'http_status_code': 0,
            'content_length': 0,
            'uses_https': 0,
            'domain_age_days': 0,
            'is_new_domain': 1,
            'has_registrar': 0
        }