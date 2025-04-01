from flask import Flask, request, jsonify
from cipher.rsa import RSACipher
from cipher.ecc import ECCipher

app = Flask(__name__)

# RSA CIPHER ALGORITHM
rsa_cipher = RSACipher()

@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    try:
        rsa_cipher.generate_keys()
        return jsonify({'message': 'Keys generated successfully!'})
    except Exception as e:
        return jsonify({'error': f'Failed to generate keys: {str(e)}'}), 500

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    data = request.json
    if not data or 'message' not in data or 'key_type' not in data:
        return jsonify({'error': 'Invalid input! Required fields: message, key_type'}), 400

    message = data['message']
    key_type = data['key_type']

    try:
        private_key, public_key = rsa_cipher.load_keys()
        if key_type == 'public':
            key = public_key
        elif key_type == 'private':
            key = private_key
        else:
            return jsonify({'error': 'Invalid key type!'}), 400

        encrypted_message = rsa_cipher.encrypt(message, key)
        encrypted_hex = encrypted_message.hex()
        return jsonify({'encrypted_message': encrypted_hex})
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    data = request.json
    if not data or 'ciphertext' not in data or 'key_type' not in data:
        return jsonify({'error': 'Invalid input! Required fields: ciphertext, key_type'}), 400

    ciphertext_hex = data['ciphertext']
    key_type = data['key_type']

    try:
        private_key, public_key = rsa_cipher.load_keys()
        if key_type == 'public':
            key = public_key
        elif key_type == 'private':
            key = private_key
        else:
            return jsonify({'error': 'Invalid key type!'}), 400

        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_message = rsa_cipher.decrypt(ciphertext, key)
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():
    data = request.json
    if not data or 'message' not in data:
        return jsonify({'error': 'Invalid input! Required field: message'}), 400

    message = data['message']

    try:
        private_key, _ = rsa_cipher.load_keys()
        signature = rsa_cipher.sign(message, private_key)
        signature_hex = signature.hex()
        return jsonify({'signature': signature_hex})
    except Exception as e:
        return jsonify({'error': f'Signing failed: {str(e)}'}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    data = request.json
    if not data or 'message' not in data or 'signature' not in data:
        return jsonify({'error': 'Invalid input! Required fields: message, signature'}), 400

    message = data['message']
    signature_hex = data['signature']

    try:
        _, public_key = rsa_cipher.load_keys()
        signature = bytes.fromhex(signature_hex)
        is_verified = rsa_cipher.verify(message, signature, public_key)
        return jsonify({'is_verified': is_verified})
    except Exception as e:
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500

# EC CIPHER ALGORITHM
ecc_cipher = ECCipher()

@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    try:
        ecc_cipher.generate_keys()
        return jsonify({'message': 'Keys generated successfully!'})
    except Exception as e:
        return jsonify({'error': f'Failed to generate keys: {str(e)}'}), 500

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign_message():
    data = request.json
    if not data or 'message' not in data:
        return jsonify({'error': 'Invalid input! Required field: message'}), 400

    message = data['message']

    try:
        private_key, _ = ecc_cipher.load_keys()
        signature = ecc_cipher.sign(message, private_key)
        signature_hex = signature.hex()
        return jsonify({'signature': signature_hex})
    except Exception as e:
        return jsonify({'error': f'Signing failed: {str(e)}'}), 500

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify_signature():
    data = request.json
    if not data or 'message' not in data or 'signature' not in data:
        return jsonify({'error': 'Invalid input! Required fields: message, signature'}), 400

    message = data['message']
    signature_hex = data['signature']

    try:
        _, public_key = ecc_cipher.load_keys()
        signature = bytes.fromhex(signature_hex)
        is_verified = ecc_cipher.verify(message, signature, public_key)
        return jsonify({'is_verified': is_verified})
    except Exception as e:
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)