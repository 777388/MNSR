import shodan
import socket
import ssl
import dns.resolver
from waybackurls import waybackurls
import requests
import re
print("python3 MNSR.py shodansearchterm cachesearch")
# Shodan API key
api_key = "YOUR_API_KEY"
api = shodan.Shodan(api_key)

# Search term for Shodan
search_term = sys.argv[1]

# Perform the search
results = api.search(search_term)

# Extract IPs from the search results
ips = [result['ip_str'] for result in results['matches']]

# Initialize lists to store the domains, subdomains, and URLs
domains = []
urls = []

# Perform certificate, DNS, and CNAME resolution to find virtual servers domains and subdomains
for ip in ips:
    try:
        cert = ssl.get_server_certificate((ip, 443))
        subject = dict(x[0] for x in ssl.PEM_cert_to_DER_cert(cert).get_subject().get_components())
        domain = subject['CN']
        domains.append(domain)

        # Perform DNS resolution to find subdomains
        answers = dns.resolver.query(domain, 'CNAME')
        for rdata in answers:
            domains.append(rdata.target.to_text())

        # Use waybackurls to find URLs related to the domain
        for url in waybackurls.search(domain):
            urls.append(url)
    except:
        pass

# Search term to grep for in the response of each URL
search_term = sys.argv[2]

# Iterate over all URLs and grep for the search term
for url in urls:
    try:
        response = requests.get(url)
        if re.search(search_term, response.text):
            print(f"Search term found in URL: {url}")
    except:
        pass
