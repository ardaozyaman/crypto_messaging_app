# Kriptografi Mesajlaşma Uygulaması - Kurulum ve Kullanım Kılavuzu

## Proje Hakkında

Bu uygulama, kriptografi dersi için geliştirilmiş güvenli bir mesajlaşma platformudur. Uygulama, kullanıcılar arasında şifrelenmiş mesajlaşma sağlar ve aşağıdaki özelliklere sahiptir:

- Kullanıcı şifreleri SHA-256 ile özetlenerek saklanır
- Her kullanıcı için RSA anahtar çifti (public key ve private key) oluşturulur
- Mesajlar alıcının public key'i ile şifrelenir ve sadece alıcının private key'i ile çözülebilir
- Metin, görsel ve ses dosyaları güvenli şekilde iletilebilir

## Teknik Özellikler

- **Programlama Dili:** Python
- **Web Framework:** Flask
- **Şifreleme Kütüphaneleri:** cryptography, hashlib, rsa
- **Veri Saklama:** JSON dosyaları
- **Desteklenen Mesaj Türleri:** Metin (.txt), Görsel (.jpg/.png), Ses (.mp3/.wav)

## Kurulum

### Gereksinimler

- Python 3.6 veya üzeri
- pip (Python paket yöneticisi)

### Adımlar

1. Proje dosyalarını bilgisayarınıza indirin
2. Komut satırında proje dizinine gidin
3. Gerekli paketleri yükleyin:
   ```
   pip install -r requirements.txt
   ```
4. Uygulamayı başlatın:
   ```
   python app.py
   ```
5. Web tarayıcınızda `http://localhost:5000` adresine gidin

## Kullanım

### Kayıt ve Giriş

1. Ana sayfada "Kayıt Ol" butonuna tıklayın
2. Kullanıcı adı ve şifre belirleyin
3. Kayıt işlemi tamamlandığında, giriş sayfasına yönlendirileceksiniz
4. Kullanıcı adı ve şifrenizle giriş yapın

### Mesaj Gönderme

1. Kontrol panelinde "Yeni Mesaj Gönder" bölümünü kullanın
2. Mesaj türünü seçin (Metin, Görsel veya Ses)
3. Alıcıyı seçin
4. Mesaj içeriğini girin veya dosya yükleyin
5. "Gönder" butonuna tıklayın

### Mesajları Görüntüleme

1. Kontrol panelinde "Gelen Mesajlar" bölümünde tüm mesajlarınızı görebilirsiniz
2. Mesajlar otomatik olarak çözülür ve türüne göre görüntülenir

## Test Kullanıcıları

Uygulama ilk çalıştırıldığında otomatik olarak 5 test kullanıcısı oluşturulur:

- Kullanıcı Adı: ahmet, Şifre: ahmet
- Kullanıcı Adı: mehmet, Şifre: mehmet
- Kullanıcı Adı: ayse, Şifre: ayse
- Kullanıcı Adı: fatma, Şifre: fatma
- Kullanıcı Adı: ali, Şifre: ali

## Güvenlik Özellikleri

### Şifre Güvenliği

Kullanıcı şifreleri SHA-256 algoritması ile özetlenerek saklanır. Bu sayede, veritabanına erişim sağlansa bile şifreler açık metin olarak görüntülenemez.

### Asimetrik Şifreleme

Uygulama, RSA asimetrik şifreleme algoritmasını kullanır:

1. Her kullanıcı için 2048-bit RSA anahtar çifti oluşturulur
2. Public key'ler ortak bir JSON dosyasında saklanır
3. Private key'ler kullanıcıya özel JSON dosyasında saklanır
4. Mesajlar alıcının public key'i ile şifrelenir
5. Şifrelenmiş mesajlar sadece alıcının private key'i ile çözülebilir

### Mesaj Güvenliği

Tüm mesaj türleri (metin, görsel, ses) şifrelenerek iletilir ve saklanır. Büyük dosyalar için parçalı şifreleme kullanılır.

## Dosya Yapısı

- `app.py`: Ana uygulama dosyası
- `requirements.txt`: Gerekli Python paketleri
- `templates/`: HTML şablonları
  - `index.html`: Ana sayfa
  - `register.html`: Kayıt sayfası
  - `login.html`: Giriş sayfası
  - `dashboard.html`: Kontrol paneli
- `static/`: Statik dosyalar (CSS, JS, yüklenen dosyalar)
- `instance/`: Veri dosyaları
  - `users.json`: Kullanıcı bilgileri
  - `public_keys.json`: Public key'ler
  - `messages.json`: Şifrelenmiş mesajlar

## Teknik Detaylar

### Şifre Özetleme

```python
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
```

### RSA Anahtar Üretimi

```python
def generate_rsa_keys():
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
```

### Mesaj Şifreleme

```python
def encrypt_message(message, public_key_pem):
    # PEM formatındaki public key'i yükle
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    # Mesajı şifrele
    if isinstance(message, str):
        message = message.encode()
    
    # Büyük mesajlar için parçalama
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
```

### Mesaj Çözme

```python
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
```
