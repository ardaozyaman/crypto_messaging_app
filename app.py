import os
import json
import hashlib
import base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import rsa as rsa_lib

# Uygulama yapılandırması
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
app.config['USER_DATA_FILE'] = os.path.join(app.root_path, 'instance', 'users.json')
app.config['PUBLIC_KEYS_FILE'] = os.path.join(app.root_path, 'instance', 'public_keys.json')
app.config['MESSAGES_FILE'] = os.path.join(app.root_path, 'instance', 'messages.json')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

# Klasörlerin varlığını kontrol et ve oluştur
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.dirname(app.config['USER_DATA_FILE']), exist_ok=True)

# Kullanıcı verilerini yükle veya oluştur
def load_users():
    if os.path.exists(app.config['USER_DATA_FILE']):
        with open(app.config['USER_DATA_FILE'], 'r') as f:
            return json.load(f)
    return {}

# Kullanıcı verilerini kaydet
def save_users(users):
    with open(app.config['USER_DATA_FILE'], 'w') as f:
        json.dump(users, f, indent=4)

# Public key'leri yükle veya oluştur
def load_public_keys():
    if os.path.exists(app.config['PUBLIC_KEYS_FILE']):
        with open(app.config['PUBLIC_KEYS_FILE'], 'r') as f:
            return json.load(f)
    return {}

# Public key'leri kaydet
def save_public_keys(public_keys):
    with open(app.config['PUBLIC_KEYS_FILE'], 'w') as f:
        json.dump(public_keys, f, indent=4)

# Mesajları yükle veya oluştur
def load_messages():
    if os.path.exists(app.config['MESSAGES_FILE']):
        with open(app.config['MESSAGES_FILE'], 'r') as f:
            return json.load(f)
    return {}

# Mesajları kaydet
def save_messages(messages):
    with open(app.config['MESSAGES_FILE'], 'w') as f:
        json.dump(messages, f, indent=4)

# Şifre özetleme fonksiyonu
def hash_password(password):
    # SHA-256 ile şifre özetleme
    return hashlib.sha256(password.encode()).hexdigest()

# RSA anahtar çifti oluşturma
def generate_rsa_keys():
    # 2048 bit RSA anahtar çifti oluştur
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Private key'i PEM formatında serialize et
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Public key'i PEM formatında serialize et
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

# Mesaj şifreleme fonksiyonu
def encrypt_message(message, public_key_pem):
    # PEM formatındaki public key'i yükle
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    # Mesajı şifrele
    if isinstance(message, str):
        message = message.encode()
    
    # Büyük mesajlar için parçalama gerekebilir
    chunk_size = 190  # RSA 2048 için güvenli boyut
    chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
    
    encrypted_chunks = []
    for chunk in chunks:
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
    
    return encrypted_chunks

# Mesaj çözme fonksiyonu
def decrypt_message(encrypted_chunks, private_key_pem):
    # PEM formatındaki private key'i yükle
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    decrypted_chunks = []
    for chunk in encrypted_chunks:
        encrypted_data = base64.b64decode(chunk)
        decrypted_chunk = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)
    
    return b''.join(decrypted_chunks)

# Ana sayfa
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Kayıt sayfası
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        
        if username in users:
            flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
            return redirect(url_for('register'))
        
        # RSA anahtar çifti oluştur
        private_key, public_key = generate_rsa_keys()
        
        # Kullanıcıyı kaydet
        users[username] = {
            'password_hash': hash_password(password),
            'private_key': private_key,
            'created_at': datetime.now().isoformat()
        }
        save_users(users)
        
        # Public key'i ortak havuza ekle
        public_keys = load_public_keys()
        public_keys[username] = public_key
        save_public_keys(public_keys)
        
        flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Giriş sayfası
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        
        if username in users and users[username]['password_hash'] == hash_password(password):
            session['username'] = username
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
    
    return render_template('login.html')

# Çıkış
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Başarıyla çıkış yaptınız.', 'info')
    return redirect(url_for('index'))

# Kontrol paneli
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    users = load_users()
    public_keys = load_public_keys()
    messages = load_messages()
    
    # Kullanıcıya gelen mesajları al
    received_messages = []
    if username in messages:
        for msg in messages[username]:
            try:
                # Şifreli mesajı çöz
                decrypted_content = decrypt_message(
                    msg['encrypted_content'],
                    users[username]['private_key']
                )
                
                # Mesaj türüne göre işle
                if msg['type'] == 'text':
                    content = decrypted_content.decode('utf-8')
                else:
                    # Dosya içeriği, frontend'de işlenecek
                    content = base64.b64encode(decrypted_content).decode('utf-8')
                
                received_messages.append({
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'type': msg['type'],
                    'content': content,
                    'timestamp': msg['timestamp']
                })
            except Exception as e:
                # Çözme hatası durumunda
                received_messages.append({
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'type': 'error',
                    'content': f"Mesaj çözülemedi: {str(e)}",
                    'timestamp': msg['timestamp']
                })
    
    return render_template('dashboard.html', 
                          username=username, 
                          users=list(public_keys.keys()),
                          messages=received_messages)

# Mesaj gönderme
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    sender = session['username']
    recipient = request.form['recipient']
    message_type = request.form['type']
    
    public_keys = load_public_keys()
    if recipient not in public_keys:
        flash('Alıcı bulunamadı.', 'danger')
        return redirect(url_for('dashboard'))
    
    messages = load_messages()
    if recipient not in messages:
        messages[recipient] = []
    
    message_id = str(len(messages.get(recipient, [])) + 1)
    timestamp = datetime.now().isoformat()
    
    try:
        if message_type == 'text':
            # Metin mesajı
            content = request.form['content']
            encrypted_content = encrypt_message(content, public_keys[recipient])
        else:
            # Dosya mesajı
            if 'file' not in request.files:
                flash('Dosya seçilmedi.', 'danger')
                return redirect(url_for('dashboard'))
            
            file = request.files['file']
            if file.filename == '':
                flash('Dosya seçilmedi.', 'danger')
                return redirect(url_for('dashboard'))
            
            # Dosya içeriğini oku ve şifrele
            file_content = file.read()
            encrypted_content = encrypt_message(file_content, public_keys[recipient])
            
            # Dosya adını ve türünü kaydet
            message_type = file.content_type.split('/')[0]  # image, audio, etc.
        
        # Mesajı kaydet
        messages[recipient].append({
            'id': message_id,
            'sender': sender,
            'type': message_type,
            'encrypted_content': encrypted_content,
            'timestamp': timestamp
        })
        
        save_messages(messages)
        flash('Mesaj başarıyla gönderildi.', 'success')
    
    except Exception as e:
        flash(f'Mesaj gönderilirken hata oluştu: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

# Uygulama başlatma
if __name__ == '__main__':
    # Test kullanıcıları oluştur
    users = load_users()
    public_keys = load_public_keys()
    
    # Eğer hiç kullanıcı yoksa, test kullanıcıları oluştur
    if not users:
        test_users = ['ahmet', 'mehmet', 'ayse', 'fatma', 'ali']
        for username in test_users:
            if username not in users:
                private_key, public_key = generate_rsa_keys()
                users[username] = {
                    'password_hash': hash_password(username),  # Basit şifre: kullanıcı adının kendisi
                    'private_key': private_key,
                    'created_at': datetime.now().isoformat()
                }
                public_keys[username] = public_key
        
        save_users(users)
        save_public_keys(public_keys)
        print("Test kullanıcıları oluşturuldu.")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
