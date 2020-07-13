from flask import Flask, flash, redirect, render_template, request, session, abort, make_response, jsonify
import os

app = Flask(__name__)

@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'code':'400', 'error': 'Bad request'}), 400)

@app.errorhandler(401)
def bad_request(error):
    return make_response(jsonify({'code':'401', 'error': 'Unauthorized'}), 401)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'code':'404', 'error': 'Not found'}), 404)

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return make_response(jsonify({"code":"200","response":"Correct credentials"}), 200)

@app.route('/login', methods=['POST'])
def do_admin_login():
    if request.is_json:
        requestJson = request.get_json()
        print("-----------------Request to login made --> ", request.get_json())
        if requestJson['password'] == 'password' and requestJson['username'] == 'admin':
            session['logged_in'] = True
            return home()
        else:
            print("Incorrect Credentials")
            abort(401)
    else:
        print("No JSON?", request)
        abort(400)

def banner():
    return """
 .-----------------. .----------------.  .----------------.  .----------------.  .----------------. 
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| | ____  _____  | || |      __      | || |  _________   | || | _____  _____ | || |    _______   | |
| ||_   \|_   _| | || |     /  \     | || | |_   ___  |  | || ||_   _||_   _|| || |   /  ___  |  | |
| |  |   \ | |   | || |    / /\ \    | || |   | |_  \_|  | || |  | | /\ | |  | || |  |  (__ \_|  | |
| |  | |\ \| |   | || |   / ____ \   | || |   |  _|      | || |  | |/  \| |  | || |   '.___`-.   | |
| | _| |_\   |_  | || | _/ /    \ \_ | || |  _| |_       | || |  |   /\   |  | || |  |`\____) |  | |
| ||_____|\____| | || ||____|  |____|| || | |_____|      | || |  |__/  \__|  | || |  |_______.'  | |
| |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------' 

     ----------------------------By David --> david.arteaga@globant.com------------------------
                                                V1.0.3
"""

if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    print (banner())
    app.run(debug=True,host='0.0.0.0', port=5000, ssl_context=('test_cert.pem', 'test_key.pem')) #secure
    #app.run(debug=True,host='0.0.0.0', port=5000) #insecure