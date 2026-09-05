from flask import Flask, render_template, request, jsonify 
from flask_cors import CORS 
import database 
import api_handler 
import security 
import json 
app = Flask(__name__) 
CORS(app) 
 
database.init_database() 
@app.route('/') 
def index(): 
    """Serve the main page""" 
    return render_template('index.html') 
@app.route('/api/check-email', methods=['POST'])
def check_email():
    """
    API endpoint to check if email is breached
    
    Request: {"email": "user@example.com"}
    Response: {
        "is_breached": true/false,
        "breach_count": 3,
        "breach_names": ["Breach1", "Breach2"]
    }
    """
    try:
        data = request.json
        email = data.get('email', '').strip()
        
        # Validation
        if not email:
            return jsonify({'error': 'Email required'}), 400
        
        if not security.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check breach
        is_breached, breach_count, breach_info = api_handler.check_email_breach(email)
        
        # Handle error messages (when breach_info is a string)
        if isinstance(breach_info, str):
            return jsonify({
                'error': breach_info,
                'email': email
            }), 500
        
        # Get detailed breach info if breached
        breach_details = []
        if is_breached:
            breach_details = api_handler.get_breach_info(email)
        
        # Save to database
        database.save_email_check(email, int(is_breached), breach_count)
        
        # Return response
        return jsonify({
            'email': email,
            'is_breached': is_breached,
            'breach_count': breach_count,
            'breach_names': breach_info,
            'breach_details': breach_details,
            'message': f"⚠️ Found in {breach_count} breach(es)!" if is_breached else "✅ Email not found in known breaches"
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/check-password', methods=['POST']) 
def check_password(): 
    """ 
    API endpoint to check if password is breached 
    Request body: {"password": "MyPassword123!"} 
    Response: { 
        "strength": "Strong", 
        "score": 5, 
        "feedback": [...], 
        "is_pwned": true/false, 
        "pwn_count": 5 
    }
    """ 
    try: 
        data = request.json 
        password = data.get('password', '') 
        if not password: 
            return jsonify({'error': 'Password required'}), 400 
        if len(password) < 1: 
            return jsonify({'error': 'Invalid password'}), 400 

        strength, score, feedback = security.analyze_password_strength(password) 

        is_pwned, pwn_count = api_handler.check_password_breach(password) 

        password_hash = security.hash_password(password) 

        database.save_password_check(password_hash, int(is_pwned), pwn_count) 
        return jsonify({ 
            'strength': strength, 
            'score': score, 
            'feedback': feedback, 
            'is_pwned': is_pwned, 
            'pwn_count': pwn_count, 
            'message': f"This password has been seen {pwn_count} times in breaches" if is_pwned else "This password has not been found"
        }), 200 
    except Exception as e: 
        return jsonify({'error': str(e)}), 500 
@app.route('/api/history/emails', methods=['GET']) 
def email_history(): 
    """Get email check history""" 
    try: 
        history = database.get_email_history() 
        history_list = [] 
        for item in history: 
            history_list.append({ 
                'email': item[0], 
                'is_breached': bool(item[1]), 
                'breach_count': item[2], 
                'checked_at': item[3] 
            }) 
        return jsonify({'history': history_list}), 200 
    except Exception as e: 
        return jsonify({'error': str(e)}), 500 
@app.route('/api/history/passwords', methods=['GET']) 
def password_history(): 
    """Get password check history""" 
    try: 
        history = database.get_password_history() 
        history_list = [] 
        for item in history: 
            history_list.append({ 
                'password_hash': item[0][:10] + '...',
                'password_strength': item[1], 
                'is_pwned': bool(item[2]), 
                'pwn_count': item[3], 
                'checked_at': item[4] 
            }) 
        return jsonify({'history': history_list}), 200 
    except Exception as e: 
        return jsonify({'error': str(e)}), 500 
@app.route('/api/clear-history', methods=['POST']) 
def clear_history(): 
    """Clear all history""" 
    try: 
        database.clear_history() 
        return jsonify({'message': 'History cleared'}), 200 
    except Exception as e: 
        return jsonify({'error': str(e)}), 500 
@app.errorhandler(404) 
def not_found(e): 
    return jsonify({'error': 'Not found'}), 404 
@app.errorhandler(500) 
def server_error(e): 
    return jsonify({'error': 'Server error'}), 500 
if __name__ == '__main__': 
    app.run(debug=True, port=5000)