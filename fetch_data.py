import pymongo
import datetime

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["cti_dashboard"]
collection = db["threat_data"]

# Remove old data to avoid duplicates
collection.delete_many({})

# Sample threat intelligence data
sample_data = [
    {"indicator": "45.83.23.12", "type": "ip", "threat": "Malware C2 Server", "risk": 85, "date": datetime.datetime.now()},
    {"indicator": "secure-login-bank.com", "type": "domain", "threat": "Phishing Site", "risk": 92, "date": datetime.datetime.now()},
    {"indicator": "malicious-offer.xyz", "type": "domain", "threat": "Scam / Fraud", "risk": 78, "date": datetime.datetime.now()},
    {"indicator": "45.83.23.12", "type": "ip", "threat": "Malware C2 Server", "risk": 85, "source": "ThreatFox", "date": datetime.datetime.now()},
    {"indicator": "secure-login-bank.com", "type": "domain", "threat": "Credential Phishing Domain", "risk": 92, "source": "PhishTank", "date": datetime.datetime.now()},
    {"indicator": "malicious-offer.xyz", "type": "domain", "threat": "Fraud / Scam Landing Page", "risk": 78, "source": "Open Source", "date": datetime.datetime.now()},
    {"indicator": "113.131.200.24", "type": "ip", "threat": "Reported Abusive IP", "risk": 70, "source": "AbuseIPDB", "date": datetime.datetime.now()},
    {"indicator": "193.46.255.20", "type": "ip", "threat": "Botnet / Suspicious Traffic", "risk": 80, "source": "AbuseIPDB", "date": datetime.datetime.now()},
    {"indicator": "35.222.25.16", "type": "ip", "threat": "Suspicious Infrastructure", "risk": 65, "source": "ThreatFeed", "date": datetime.datetime.now()},
    {"indicator": "http://account-verify-security-login.com/login", "type": "url", "threat": "Credential Phishing (Fake Login Page)", "risk": 91, "source": "PhishTank/OpenPhish", "date": datetime.datetime.now()},
    {"indicator": "http://free-gift-card.offer-now.xyz/claim", "type": "url", "threat": "Phishing / Fraud Landing Page", "risk": 75, "source": "Open Source", "date": datetime.datetime.now()},
    {"indicator": "bad-rewards-login.net", "type": "domain", "threat": "Credential Harvesting Domain", "risk": 88, "source": "Manual/OSINT", "date": datetime.datetime.now()},
    {"indicator": "159.65.185.221", "type": "ip", "threat": "Malicious Proxy / Abuse Reports", "risk": 82, "source": "AbuseIPDB", "date": datetime.datetime.now()},
    {"indicator": "45.140.17.124", "type": "ip", "threat": "Suspicious C2 / Malware Hosting", "risk": 86, "source": "ThreatFox", "date": datetime.datetime.now()},
    {"indicator": "login-secure-bank-support.com/account", "type": "url", "threat": "Phishing URL (Fake Bank Login)", "risk": 93, "source": "OpenPhish/PhishTank", "date": datetime.datetime.now()}
]



collection.insert_many(sample_data)
print("✅ Data inserted into MongoDB!")
