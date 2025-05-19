# Kriptografi Mesajlaşma Uygulaması: Teknik Detaylar ve Soru-Cevap Rehberi

Bu rehber, kriptografi projenizin teknik detaylarını basit ve anlaşılır bir şekilde açıklamaktadır. Hocanızın sorabileceği sorular ve bunlara verebileceğiniz cevaplar formatında hazırlanmıştır.

## 1. Temel Kriptografi Kavramları

### S: Kriptografi nedir ve bu projede neden önemlidir?
**C:** Kriptografi, bilgiyi güvenli bir şekilde iletmek ve saklamak için matematiksel yöntemler kullanan bir bilim dalıdır. Bu projede kriptografi, kullanıcıların birbirlerine gönderdikleri mesajların başkaları tarafından okunamayacak şekilde şifrelenmesi için kullanılmıştır. Yani mesajlarımızın gizliliğini sağlamak için kriptografiyi kullandık.

### S: Şifreleme (encryption) ve şifre çözme (decryption) ne demektir?
**C:** Şifreleme, okunabilir bir metni (düz metin) matematiksel algoritmalar kullanarak anlaşılamaz hale (şifreli metin) getirme işlemidir. Şifre çözme ise bu işlemin tersidir, yani şifreli metni tekrar okunabilir hale getirme işlemidir. Projemizde, bir kullanıcının gönderdiği mesaj şifrelenir ve sadece alıcı tarafından çözülebilir.

### S: Simetrik ve asimetrik şifreleme arasındaki fark nedir?
**C:** 
- **Simetrik şifreleme:** Hem şifreleme hem de şifre çözme için aynı anahtar kullanılır. Hızlıdır ama anahtar paylaşımı sorunu vardır.
- **Asimetrik şifreleme:** İki farklı ama matematiksel olarak ilişkili anahtar kullanılır: public key (herkese açık anahtar) ve private key (özel anahtar). Mesajlar public key ile şifrelenir ve sadece ilgili private key ile çözülebilir. Projemizde RSA asimetrik şifreleme kullanılmıştır.

## 2. Projede Kullanılan Kriptografik Yöntemler

### S: Projede hangi şifreleme algoritmaları kullanıldı?
**C:** Projemizde iki temel kriptografik yöntem kullandık:
1. **SHA-256:** Kullanıcı şifrelerini güvenli şekilde saklamak için kullanılan bir özet (hash) fonksiyonu
2. **RSA:** Kullanıcılar arasındaki mesajları şifrelemek için kullanılan asimetrik şifreleme algoritması

### S: SHA-256 nedir ve projede nasıl kullanıldı?
**C:** SHA-256, bir veriyi sabit uzunlukta (256 bit) bir özete dönüştüren kriptografik bir özet fonksiyonudur. Özellikleri:
- Tek yönlüdür (geri döndürülemez)
- Aynı girdi her zaman aynı özeti üretir
- Farklı girdiler neredeyse her zaman farklı özetler üretir

Projemizde kullanıcı şifrelerini açık metin olarak saklamak yerine SHA-256 ile özetleyerek sakladık. Böylece veritabanımız ele geçirilse bile şifreler açığa çıkmaz.

```python
def hash_password(password):
    # SHA-256 ile şifre özetleme
    return hashlib.sha256(password.encode()).hexdigest()
```

### S: RSA algoritması nasıl çalışır?
**C:** RSA, asimetrik şifreleme için kullanılan matematiksel bir algoritmadır. Çalışma prensibi:

1. İki büyük asal sayı seçilir (p ve q)
2. Bu sayılar çarpılarak n = p × q elde edilir
3. Euler fonksiyonu hesaplanır: φ(n) = (p-1) × (q-1)
4. Public key (e) ve private key (d) oluşturulur öyle ki (e × d) mod φ(n) = 1 olsun
5. Public key (e, n) ve private key (d, n) olarak tanımlanır

Şifreleme: C = M^e mod n (M: mesaj, C: şifreli mesaj)
Şifre çözme: M = C^d mod n

Projemizde her kullanıcı için 2048-bit RSA anahtar çifti oluşturulur.

### S: Projede RSA anahtarları nasıl oluşturuluyor ve saklanıyor?
**C:** Projemizde Python'un cryptography kütüphanesini kullanarak RSA anahtar çiftleri oluşturuyoruz:

```python
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
```

Anahtarların saklanması:
- Public key'ler ortak bir JSON dosyasında saklanır (public_keys.json)
- Private key'ler kullanıcıya özel JSON dosyasında saklanır (users.json)

## 3. Mesaj Şifreleme ve Çözme Süreci

### S: Bir mesaj nasıl şifreleniyor?
**C:** Mesaj şifreleme süreci şu adımlardan oluşur:

1. Alıcının public key'i public_keys.json dosyasından alınır
2. Mesaj (metin, görsel veya ses) önce byte dizisine dönüştürülür
3. RSA 2048-bit ile şifrelenebilecek maksimum boyut 245 byte olduğundan, büyük mesajlar 190 byte'lık parçalara bölünür
4. Her parça alıcının public key'i ile şifrelenir
5. Şifrelenmiş parçalar Base64 formatına dönüştürülür ve bir liste olarak saklanır

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

### S: Şifrelenmiş bir mesaj nasıl çözülüyor?
**C:** Mesaj çözme süreci şu adımlardan oluşur:

1. Alıcı kendi private key'ini kullanır
2. Şifrelenmiş her parça Base64 formatından çözülür
3. Her parça private key ile şifresi çözülür
4. Çözülen parçalar birleştirilir
5. Mesaj türüne göre (metin, görsel, ses) uygun formatta gösterilir

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

### S: Neden mesajları parçalara bölerek şifreliyoruz?
**C:** RSA algoritması, matematiksel sınırlamalar nedeniyle bir seferde şifreleyebileceği veri miktarında kısıtlıdır. 2048-bit RSA için bu sınır yaklaşık 245 byte'tır. Güvenlik için padding (dolgu) kullanıldığında, güvenli şekilde şifrelenebilecek veri miktarı 190 byte civarına düşer. Bu nedenle, büyük mesajları (özellikle görsel ve ses dosyaları) parçalara bölerek şifrelemek zorundayız. Her parça ayrı ayrı şifrelenir ve alıcı tarafında tekrar birleştirilir.

## 4. Güvenlik Özellikleri ve Sınırlamaları

### S: Projede kullanılan güvenlik özellikleri nelerdir?
**C:** Projemizde şu güvenlik özellikleri bulunmaktadır:

1. **Şifre güvenliği:** Kullanıcı şifreleri SHA-256 ile özetlenerek saklanır
2. **Asimetrik şifreleme:** RSA 2048-bit ile end-to-end şifreleme sağlanır
3. **Anahtar yönetimi:** Her kullanıcı için benzersiz anahtar çifti oluşturulur
4. **Mesaj gizliliği:** Mesajlar sadece hedeflenen alıcı tarafından çözülebilir
5. **Farklı mesaj türleri desteği:** Metin, görsel ve ses dosyaları güvenli şekilde iletilebilir


## 5. Veri Saklama ve Yönetimi

### S: Projede veriler nasıl saklanıyor?
**C:** Projemizde veriler JSON dosyalarında saklanmaktadır:

1. **users.json:** Kullanıcı bilgileri (kullanıcı adı, şifre özeti, private key)
2. **public_keys.json:** Tüm kullanıcıların public key'leri
3. **messages.json:** Şifrelenmiş mesajlar ve meta verileri

Örnek users.json yapısı:
```json
{
    "ahmet": {
        "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
        "created_at": "2025-05-17T14:23:45.123456"
    }
}
```

### S: Mesajlar nasıl saklanıyor?
**C:** Mesajlar, alıcıya göre organize edilmiş bir yapıda saklanır:

```json
{
    "ahmet": [
        {
            "id": "1",
            "sender": "mehmet",
            "type": "text",
            "encrypted_content": ["BASE64_ENCODED_CHUNK1", "BASE64_ENCODED_CHUNK2"],
            "timestamp": "2025-05-17T14:30:12.123456"
        },
        {
            "id": "2",
            "sender": "ayse",
            "type": "image",
            "encrypted_content": ["BASE64_ENCODED_CHUNK1", "BASE64_ENCODED_CHUNK2", "..."],
            "timestamp": "2025-05-17T14:35:22.123456"
        }
    ]
}
```

## 6. Uygulama Mimarisi ve Akışı

### S: Uygulamanın genel mimarisi nasıldır?
**C:** Uygulamamız Flask web framework'ü üzerine kurulmuş bir MVC (Model-View-Controller) benzeri mimari kullanır:

1. **Model:** JSON dosyaları (users.json, public_keys.json, messages.json)
2. **View:** HTML şablonları (templates klasöründe)
3. **Controller:** app.py içindeki route fonksiyonları

### S: Bir kullanıcı kaydı sırasında neler oluyor?
**C:** Kullanıcı kaydı şu adımlardan oluşur:

1. Kullanıcı, kayıt formunda kullanıcı adı ve şifre girer
2. Sistem, kullanıcı adının benzersiz olup olmadığını kontrol eder
3. Şifre SHA-256 algoritması ile özetlenir
4. Kullanıcı için 2048-bit RSA anahtar çifti oluşturulur
5. Kullanıcı bilgileri (kullanıcı adı, şifre özeti, private key) users.json dosyasına kaydedilir
6. Kullanıcının public key'i public_keys.json dosyasına eklenir
7. Kullanıcı giriş sayfasına yönlendirilir

### S: Bir mesaj gönderme işlemi nasıl gerçekleşir?
**C:** Mesaj gönderme işlemi şu adımlardan oluşur:

1. Kullanıcı, alıcıyı seçer ve mesaj içeriğini girer (metin) veya dosya yükler (görsel/ses)
2. Alıcının public key'i public_keys.json dosyasından alınır
3. Mesaj içeriği, alıcının public key'i ile şifrelenir
4. Şifrelenmiş mesaj, alıcının adıyla ilişkilendirilerek messages.json dosyasına kaydedilir
5. Kullanıcıya mesajın başarıyla gönderildiği bildirilir

### S: Bir mesaj alma ve görüntüleme işlemi nasıl gerçekleşir?
**C:** Mesaj alma ve görüntüleme işlemi şu adımlardan oluşur:

1. Kullanıcı dashboard sayfasını açtığında, sistem messages.json dosyasından kullanıcıya gelen mesajları kontrol eder
2. Her mesaj için, kullanıcının private key'i ile şifre çözme işlemi gerçekleştirilir
3. Çözülen mesajlar, türlerine göre (metin, görsel, ses) uygun formatta gösterilir
4. Metin mesajları doğrudan gösterilir
5. Görsel ve ses dosyaları için uygun medya oynatıcıları kullanılır

## 7. Kriptografi Kütüphaneleri ve Fonksiyonları

### S: Projede hangi kriptografi kütüphaneleri kullanıldı?
**C:** Projemizde şu kriptografi kütüphaneleri kullanıldı:

1. **hashlib:** Şifre özetleme (SHA-256) için
2. **cryptography:** RSA anahtar üretimi, şifreleme ve şifre çözme için
3. **base64:** Şifrelenmiş verilerin kodlanması ve depolanması için
4. **rsa:** Bazı yardımcı fonksiyonlar için

### S: OAEP padding nedir ve neden kullanılır?
**C:** OAEP (Optimal Asymmetric Encryption Padding), RSA şifreleme sırasında kullanılan bir dolgu (padding) mekanizmasıdır. Şu amaçlarla kullanılır:

1. **Determinizmi önlemek:** Aynı mesaj her şifrelendiğinde farklı şifreli metin üretilmesini sağlar
2. **Güvenliği artırmak:** Matematiksel saldırılara karşı koruma sağlar
3. **Mesaj uzunluğunu standartlaştırmak:** RSA'nın gerektirdiği sabit uzunlukta girdiler oluşturur

Projemizde OAEP padding şu şekilde kullanılmıştır:

```python
padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)
```

### S: PEM formatı nedir ve anahtarlar neden bu formatta saklanır?
**C:** PEM (Privacy Enhanced Mail), kriptografik anahtarlar, sertifikalar ve diğer veriler için kullanılan bir kodlama formatıdır. Özellikleri:

1. Base64 kodlaması kullanır
2. "-----BEGIN" ve "-----END" etiketleri ile sınırlandırılır
3. Metin tabanlıdır, bu nedenle JSON gibi formatlarda saklanabilir
4. Standart bir format olduğu için farklı kütüphaneler ve sistemler arasında uyumludur

Projemizde anahtarlar PEM formatında saklanır çünkü:
- Metin tabanlı olduğu için JSON dosyalarında kolayca saklanabilir
- Standart bir format olduğu için cryptography kütüphanesi tarafından kolayca işlenebilir
- İnsan tarafından okunabilir (en azından formatı tanınabilir)
