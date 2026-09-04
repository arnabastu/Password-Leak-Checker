import hashlib
import re

def hash_password(password):
    """
    SHA-1 hash the password (for k-anonymity with HIBP API)
    Returns uppercase hash
    """

    return hashlib.sha1(password.encode()).hexdigest().upper()

def get_password_hash_prefix(password_hash):
    """
    Get first 5 characters of hash (for k-anonymity)
    This is sent to HIBP API, not the full hash
    """
    return password_hash[:5]

def analyze_password_strength(password):
    """
    Analyze password strength and return score + feedback
    Returns: (strength_level , score , feedback)
    """
    score = 0
    feedback = []

    if len(password)>=8:
        score +=1
    else:
        feedback.append("Password is too short. Use at least 8 characters")
    if len(password)>=12:
        score +=1
    else:
        feedback.append("At least 12 characters (Recommended)")
    if re.search(r'[~!@#$%^&*()_+{}|:"<>?\-=\[\] \\;\' ,./]' ,password):
        score +=1
    else:
        feedback.append("Add special characters")
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid repeating characters(aaa, 111)")
        score = max(0 , score - 1)


    if score>= 6:
        strength = "Very Strong"
    elif score>=5:
        strength = "Strong"
    elif score>=4:
        strength = "Good"
    elif score>=3:
        strength = "Fair"
    else:
        strength = "Weak"

    if len(password) >= 8: 
        feedback.insert(0, " Good length") 
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password): 
        feedback.insert(0, " Mixed case") 
    if re.search(r'\d', password): 
        feedback.insert(0, " Contains numbers") 
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password): 
        feedback.insert(0, " Special characters included") 
    return strength, score, feedback 
def validate_email(email): 
    """Basic email validation""" 
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' 
    return re.match(pattern, email) is not None 


