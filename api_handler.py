import requests
import time
from security import hash_password, get_password_hash_prefix, validate_email

HIBP_BREACHED_EMAIL_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_PASSWORD_URL = "https://api.pwnedpasswords.com/range"

HEADERS ={
    'User-Agent': 'PasswordLeakCheacker(https://github.com/arnabastu/Password-Leak-Checker)'
}

def check_email_breaches(email):
    """Check if email has appeared in known data breaches"""

    if not validate_email(email):
        return False, 0 , "Invalid email format"
    try:
        time.sleep(1.5)
        response = requests.get(
            HIBP_BREACHED_EMAIL_URL,
            params= {'email' :email},
            headers= HEADERS,
            timeout = 10
        )
        if response.status_code == 200:
            breaches = response.json()
            breach_count = len(breaches)
            breach_names = [breach['Name'] for breach in breaches]
            return True, breach_count , breach_names
        elif response.status_code == 404:
            return False, 0 , []
        else:
            return False, f"API error {response.status_code}"
    except requests.exceptions.Timeout:
        return False, 0 , "Request Timeout"
    except requests.exceptions.RequestException as e:
        return False, 0 , f"Error:{str(e)}"
def check_password_breach(password):
    """Check if password has appeared in known data breaches"""
    try:
        time.sleep(1.5)
        hash_pw = hash_password(password)
        prefix = get_password_hash_prefix(hash_pw)

        response = requests.get(
            HIBP_PASSWORD_URL,
            params={'prefix': prefix},
            headers = HEADERS,
            timeout=10
        )
        if response.status_code == 200:
            hashes = response.text.split('\r\n')
            hash_map = dict()
            for hash_line in hashes:
                hash_suffix , count = hash_line.split(':')
                full_hash = prefix + hash_suffix
                if full_hash == hash_pw:
                    return True , int(count)
            return False, 0
        else:
            return False, 0

    except requests.exceptions.Timeout:
        return False , 0
    except requests.exceptions.RequestException as e:
        return False, 0 
def get_breached_info(email):
    try:
        time.sleep(1.5)
        response = requests.get(
            HIBP_BREACHED_EMAIL_URL,
            params={'email': email , 'includeUnverfied': 'false'},
            headers = HEADERS,
            timeout=10
        )
        if response.status_code == 200:
            breaches = response.json()
            breach_info = []
            for breach in breaches:
                breach_info.append({
                    'name': breach.get('Name' , 'Unknown'),
                    'date': breach.get('BreachDate', 'Unknown'),
                    'data_compromised': breach.get('Title' , 'Unknown'),
                    'compromised_count': breach.get('PwnCount', 0),
                })
            return breach_info
        return []
    except:
        return[]

                                   
