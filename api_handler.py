import requests
import time
from security import hash_password, get_password_hash_prefix, validate_email

HIBP_BREACHED_EMAIL_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range"

HEADERS ={
    'User-Agent': 'PasswordLeakCheacker(https://github.com/arnabastu/Password-Leak-Checker)'
}

EMAILREP_API_KEY = ""

# Using EmailRep API (more reliable)

def check_email_breach(email):
    """
    Check if email is breached using FREE EmailRep API
    Returns: (is_breached, breach_count, breach_list)
    """
    
    if not validate_email(email):
        return False, 0, "Invalid email format"
    
    try:
        time.sleep(1)
        
        url = f"https://emailrep.io/{email}"
        headers = {
            'User-Agent': 'PasswordLeakChecker'
        }
        if EMAILREP_API_KEY:
            headers['Key'] = EMAILREP_API_KEY
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('compromised'):
                sources = data.get('sources', {})
                breach_sources = [s for s in sources.keys() if sources[s]]
                return True, len(breach_sources), breach_sources
            else:
                return False, 0, []
        
        elif response.status_code == 429:
            return False, 0, "Email check service requires an API key (unauthenticated access disabled)"
        
        else:
            return False, 0, f"Email check API error (status {response.status_code})"
    
    except requests.exceptions.Timeout:
        return False, 0, "Request timeout"
    except requests.exceptions.ConnectionError:
        return False, 0, "Connection error"
    except Exception as e:
        return False, 0, str(e)


def get_breach_info(email):
    """Get detailed breach info"""
    try:
        time.sleep(1)
        
        url = f"https://emailrep.io/{email}"
        headers = {
            'User-Agent': 'PasswordLeakChecker'
        }
        if EMAILREP_API_KEY:
            headers['Key'] = EMAILREP_API_KEY
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('compromised'):
                sources = data.get('sources', {})
                
                breach_info = []
                for source_name, is_breached in sources.items():
                    if is_breached:
                        breach_info.append({
                            'name': source_name,
                            'date': 'Unknown',
                            'description': 'Found in this source',
                            'count': 0
                        })
                
                return breach_info
        
        return []
    except:
        return []

def check_password_breach(password):
    """Check if password has appeared in known data breaches"""
    try:
        time.sleep(1.5)
        hash_pw = hash_password(password)
        prefix = get_password_hash_prefix(hash_pw)

        response = requests.get(
            HIBP_PASSWORD_URL,
            params={'prefix': prefix},
            headers=HEADERS,
            timeout=10
        )
        if response.status_code == 200:
            hashes = response.text.split('\r\n')
            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                full_hash = prefix + hash_suffix
                if full_hash == hash_pw:
                    return True, int(count)
            return False, 0
        else:
            return False, 0
    except requests.exceptions.Timeout:
        return False, 0
    except requests.exceptions.RequestException:
        return False, 0