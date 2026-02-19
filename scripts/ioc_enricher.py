#!/usr/bin/env python3
"""
IOC Enrichment Tool - Bulk Threat Intelligence Integration
Enriches raw IOCs (IPs, domains, hashes) with VirusTotal, URLScan, Shodan data

Usage:
    python ioc_enricher.py --input iocs.txt --output results.json --api-key YOUR_VT_API_KEY
    python ioc_enricher.py --input iocs.csv --format csv --output enriched_iocs.csv
"""

import json
import csv
import argparse
import time
import requests
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import hashlib
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ioc_enricher.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IOCEnricher:
    """Main IOC enrichment class"""
    
    def __init__(self, vt_api_key: str, cache_file: str = 'ioc_cache.json'):
        """Initialize with API credentials"""
        self.vt_api_key = vt_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.cache_file = cache_file
        self.cache = self.load_cache()
        self.rate_limit = {'calls': 0, 'reset_time': time.time()}
        self.enriched_count = 0
        self.cached_count = 0
        
    def load_cache(self) -> Dict:
        """Load cached enrichment data from disk"""
        if Path(self.cache_file).exists():
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        return {}
    
    def save_cache(self):
        """Persist cache to disk"""
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)
        logger.info(f"Cache saved: {len(self.cache)} entries")
    
    def classify_ioc(self, ioc: str) -> str:
        """Classify IOC type: ipv4, domain, hash"""
        # IPv4 detection
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ioc):
            return 'ipv4'
        
        # Domain detection
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', ioc):
            return 'domain'
        
        # SHA256/MD5/SHA1 hash detection
        if len(ioc) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc):
            return 'sha256'
        if len(ioc) == 32 and all(c in '0123456789abcdefABCDEF' for c in ioc):
            return 'md5'
        if len(ioc) == 40 and all(c in '0123456789abcdefABCDEF' for c in ioc):
            return 'sha1'
        
        return 'unknown'
    
    def rate_limit_wait(self):
        """Enforce API rate limits (4 requests/minute for free tier)"""
        current_time = time.time()
        
        # Reset counter every 60 seconds
        if current_time - self.rate_limit['reset_time'] >= 60:
            self.rate_limit['calls'] = 0
            self.rate_limit['reset_time'] = current_time
        
        # Wait if rate limit exceeded
        if self.rate_limit['calls'] >= 4:
            sleep_time = 60 - (current_time - self.rate_limit['reset_time'])
            logger.warning(f"Rate limit approaching. Waiting {sleep_time:.1f}s...")
            time.sleep(max(0, sleep_time))
            self.rate_limit['calls'] = 0
            self.rate_limit['reset_time'] = time.time()
        
        self.rate_limit['calls'] += 1
    
    def enrich_ipv4(self, ip: str) -> Dict:
        """Enrich IPv4 address via VirusTotal"""
        # Check cache first
        if ip in self.cache:
            self.cached_count += 1
            return self.cache[ip]
        
        try:
            self.rate_limit_wait()
            headers = {"x-apikey": self.vt_api_key}
            url = f"{self.vt_base_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.warning(f"VT API error for {ip}: {response.status_code}")
                return {'ioc': ip, 'type': 'ipv4', 'error': 'api_error'}
            
            data = response.json()['data']['attributes']
            
            enrichment = {
                'ioc': ip,
                'type': 'ipv4',
                'reputation': data.get('reputation', 0),
                'last_analysis_stats': data.get('last_analysis_stats', {}),
                'last_dns_records': data.get('last_dns_records', []),
                'country': data.get('country', 'Unknown'),
                'as_owner': data.get('as_owner', 'Unknown'),
                'enriched_at': datetime.now().isoformat()
            }
            
            # Calculate risk score
            stats = enrichment['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            enrichment['malicious_ratio'] = malicious / total if total > 0 else 0
            enrichment['confidence'] = 'HIGH' if enrichment['malicious_ratio'] > 0.3 else 'MEDIUM' if enrichment['malicious_ratio'] > 0.1 else 'LOW'
            
            self.cache[ip] = enrichment
            self.enriched_count += 1
            return enrichment
            
        except Exception as e:
            logger.error(f"Error enriching {ip}: {str(e)}")
            return {'ioc': ip, 'type': 'ipv4', 'error': str(e)}
    
    def enrich_domain(self, domain: str) -> Dict:
        """Enrich domain via VirusTotal"""
        if domain in self.cache:
            self.cached_count += 1
            return self.cache[domain]
        
        try:
            self.rate_limit_wait()
            headers = {"x-apikey": self.vt_api_key}
            url = f"{self.vt_base_url}/domains/{domain}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.warning(f"VT API error for {domain}: {response.status_code}")
                return {'ioc': domain, 'type': 'domain', 'error': 'api_error'}
            
            data = response.json()['data']['attributes']
            
            enrichment = {
                'ioc': domain,
                'type': 'domain',
                'reputation': data.get('reputation', 0),
                'last_analysis_stats': data.get('last_analysis_stats', {}),
                'last_dns_records': data.get('last_dns_records', []),
                'registrar': data.get('registrar', 'Unknown'),
                'creation_date': data.get('creation_date', None),
                'last_update_date': data.get('last_update_date', None),
                'last_http_response_code': data.get('last_http_response_code', None),
                'enriched_at': datetime.now().isoformat()
            }
            
            # Calculate risk score
            stats = enrichment['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            enrichment['malicious_ratio'] = malicious / total if total > 0 else 0
            enrichment['confidence'] = 'HIGH' if enrichment['malicious_ratio'] > 0.2 else 'MEDIUM' if enrichment['malicious_ratio'] > 0.05 else 'LOW'
            
            self.cache[domain] = enrichment
            self.enriched_count += 1
            return enrichment
            
        except Exception as e:
            logger.error(f"Error enriching {domain}: {str(e)}")
            return {'ioc': domain, 'type': 'domain', 'error': str(e)}
    
    def enrich_hash(self, file_hash: str) -> Dict:
        """Enrich file hash via VirusTotal"""
        if file_hash in self.cache:
            self.cached_count += 1
            return self.cache[file_hash]
        
        try:
            self.rate_limit_wait()
            headers = {"x-apikey": self.vt_api_key}
            url = f"{self.vt_base_url}/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.warning(f"VT API error for {file_hash}: {response.status_code}")
                return {'ioc': file_hash, 'type': 'hash', 'error': 'api_error'}
            
            data = response.json()['data']['attributes']
            
            enrichment = {
                'ioc': file_hash,
                'type': 'hash',
                'names': data.get('names', []),
                'size': data.get('size', 0),
                'type_description': data.get('type_description', 'Unknown'),
                'last_analysis_stats': data.get('last_analysis_stats', {}),
                'last_submission_date': data.get('last_submission_date', None),
                'enriched_at': datetime.now().isoformat()
            }
            
            # Calculate risk score
            stats = enrichment['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            enrichment['malicious_ratio'] = malicious / total if total > 0 else 0
            enrichment['confidence'] = 'HIGH' if enrichment['malicious_ratio'] > 0.5 else 'MEDIUM' if enrichment['malicious_ratio'] > 0.1 else 'LOW'
            
            self.cache[file_hash] = enrichment
            self.enriched_count += 1
            return enrichment
            
        except Exception as e:
            logger.error(f"Error enriching {file_hash}: {str(e)}")
            return {'ioc': file_hash, 'type': 'hash', 'error': str(e)}
    
    def enrich_ioc(self, ioc: str) -> Dict:
        """Enrich IOC based on its type"""
        ioc = ioc.strip().lower()
        ioc_type = self.classify_ioc(ioc)
        
        if ioc_type == 'ipv4':
            return self.enrich_ipv4(ioc)
        elif ioc_type == 'domain':
            return self.enrich_domain(ioc)
        elif ioc_type in ('sha256', 'md5', 'sha1'):
            return self.enrich_hash(ioc)
        else:
            logger.warning(f"Unknown IOC type: {ioc}")
            return {'ioc': ioc, 'type': 'unknown', 'error': 'unknown_type'}
    
    def load_iocs(self, input_file: str) -> List[str]:
        """Load IOCs from input file (txt or csv)"""
        iocs = []
        
        try:
            with open(input_file, 'r') as f:
                content = f.read().strip()
                
                # Try CSV format first
                if input_file.endswith('.csv'):
                    reader = csv.reader(content.split('\n'))
                    for row in reader:
                        if row and row[0].strip():
                            iocs.append(row[0].strip())
                else:
                    # Plain text, one IOC per line
                    iocs = [line.strip() for line in content.split('\n') if line.strip()]
            
            logger.info(f"Loaded {len(iocs)} IOCs from {input_file}")
            return iocs
        
        except Exception as e:
            logger.error(f"Error loading IOCs: {str(e)}")
            return []
    
    def save_results(self, results: List[Dict], output_file: str, format: str = 'json'):
        """Save enrichment results to file"""
        try:
            if format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
            
            elif format == 'csv':
                if not results:
                    return
                
                fieldnames = list(results[0].keys())
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
            
            logger.info(f"Results saved to {output_file}")
        
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

def main():
    parser = argparse.ArgumentParser(
        description='IOC Enrichment Tool - Bulk threat intelligence integration'
    )
    parser.add_argument('--input', required=True, help='Input file with IOCs (txt or csv)')
    parser.add_argument('--output', required=True, help='Output file for results (json or csv)')
    parser.add_argument('--api-key', required=True, help='VirusTotal API key')
    parser.add_argument('--format', default='json', choices=['json', 'csv'], 
                        help='Output format (default: json)')
    
    args = parser.parse_args()
    
    # Initialize enricher
    enricher = IOCEnricher(args.api_key)
    
    # Load IOCs
    iocs = enricher.load_iocs(args.input)
    if not iocs:
        logger.error("No IOCs loaded. Exiting.")
        return
    
    # Enrich each IOC
    logger.info(f"Starting enrichment of {len(iocs)} IOCs...")
    results = []
    for idx, ioc in enumerate(iocs, 1):
        logger.info(f"[{idx}/{len(iocs)}] Enriching: {ioc}")
        result = enricher.enrich_ioc(ioc)
        results.append(result)
    
    # Save cache
    enricher.save_cache()
    
    # Save results
    enricher.save_results(results, args.output, args.format)
    
    # Print summary
    logger.info(f"\n=== Enrichment Summary ===")
    logger.info(f"Total IOCs: {len(iocs)}")
    logger.info(f"Newly enriched: {enricher.enriched_count}")
    logger.info(f"From cache: {enricher.cached_count}")
    
    # Categorize by confidence
    high_confidence = [r for r in results if r.get('confidence') == 'HIGH']
    medium_confidence = [r for r in results if r.get('confidence') == 'MEDIUM']
    low_confidence = [r for r in results if r.get('confidence') == 'LOW']
    
    logger.info(f"High confidence (malicious): {len(high_confidence)}")
    logger.info(f"Medium confidence: {len(medium_confidence)}")
    logger.info(f"Low confidence: {len(low_confidence)}")

if __name__ == '__main__':
    main()
