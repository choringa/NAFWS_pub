from flask import Flask, flash, redirect, render_template, request, session, abort, make_response, jsonify, json
import os
import ecdh_security_module as ecdh
from waitress import serve

app = Flask(__name__)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'code': '400', 'error': 'Bad request'}), 400)


@app.errorhandler(401)
def bad_request(error):
    return make_response(jsonify({'code': '401', 'error': 'Unauthorized'}), 401)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'code': '404', 'error': 'Not found'}), 404)


@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return make_response(jsonify({"code": "200", "response": "Correct credentials"}), 200)

def response_login_encrypted(was_correct):
    if was_correct:
        return make_response(jsonify({"code": "200", "encrypted_data": ecdh.encrypt("{'login_correct':true}")}), 200)
    else:
        return make_response(jsonify({"code": "200", "encrypted_data": ecdh.encrypt("{'login_correct':false}")}), 200)


@app.route('/login', methods=['POST'])
def do_admin_login():
    if request.is_json:
        requestJson = request.get_json()
        app.logger.debug(f"do_admin_login: Request made --> {request.get_json()}")
        if requestJson['password'] == 'password' and requestJson['username'] == 'admin':
            app.logger.debug("do_admin_login: Correct Credentials")
            session['logged_in'] = True
            return home()
        else:
            app.logger.error("do_admin_login: Incorrect Credentials")
            abort(401)
    else:
        app.logger.error(f"do_admin_login: Bad Request, No JSON: {request}")
        abort(400)

@app.route('/login_encrypted', methods=['POST'])
def do_encrypted_login():
    if request.is_json:
        requestJson = request.get_json()
        app.logger.debug(f"do_encrypted_login: Request made --> {request.get_json()}")
        encrypted_data = requestJson["encrypted_data"]
        try:
            decryted_data = ecdh.decrypt(encrypted_data)
            if decryted_data['password'] == 'password' and decryted_data['username'] == 'admin':
                app.logger.debug("do_encrypted_login: Correct Credentials")
                session['logged_in'] = True
                return response_login_encrypted(True)
            else:
                app.logger.error("do_encrypted_login: Incorrect Credentials")
                return response_login_encrypted(False)
        except Exception as ex:
            app.logger.error(f"do_encrypted_login: Encrypted data recived:{ex}")
            abort(400)
    else:
        app.logger.error(f"do_encrypted_login: Bad Request, No JSON: {request}")
        abort(400)


@app.route('/ecdh', methods=['post'])
def do_ecdh_exchange():
    if request.is_json:
        requestJson = request.get_json()
        app.logger.debug(f"Request to /ecdh made --> {request.get_json()}")
        try:
            client_public_key = requestJson['public_key']
        except KeyError:
            app.logger.error("do_ecdh_exchange: No public key on request")
            client_public_key = ""
        shared_created = ecdh.generateSharedSecret(client_public_key)
        if(shared_created):
            app.logger.debug("do_ecdh_exchange: Correct Credentials")
            return make_response(jsonify({"code": "200", "response": {"server_public_key": {"x_coordinate": str(ecdh.server_public_key.x), "y_coordinate": str(ecdh.server_public_key.y)}}}), 200)
        else:
            app.logger.error("do_ecdh_exchange: Internal Server error creando shared key")
            return make_response(jsonify({"code": "500", "response": "Internal Server error creando shared key"}), 500)
        
    else:
        app.logger.error(f"do_ecdh_exchange: Bad Request, no JSON: {request}")


def banner():
    print("""
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
                                                V1.2.3
""")


def createApp():
    app.secret_key = os.urandom(12)
    banner()
    ecdh.generateKeys()
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=(
        'test_cert.pem', 'test_key.pem'))  # secure
    # app.run(debug=True,host='0.0.0.0', port=5000) #insecure

if __name__ == "__main__":
    #serve(app, host='0.0.0.0', port=5000, sslcontext=('test_cert.pem', 'test_key.pem'))
    #serve(app, port=5000)
    createApp()
