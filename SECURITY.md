# Güvenlik kapsamı

Honeygrid bir yerel gözlem prototipidir. Üretim SOAR/firewall, gerçek SSH emülasyonu, tam adli paket yakalama veya zero-day tespiti sağlamaz.

- Varsayılan loopback bind ayarlarını bilinçli ağ tasarımı olmadan değiştirmeyin.
- Operatör ve agent sırlarını ortam değişkenlerinde tutun. Gerçek payload, veritabanı ve çalışma loglarını issue/PR içine koymayın.
- Honeypot girişleri güvenilmeyen metindir; panel bunları HTML olarak yorumlamaz. Aynı ilke yeni ekranlarda da korunmalı.
- WebSocket yalnızca oturum açmış operatörün `/topic/attacks` aboneliğine izin verir; istemciden olay yayınlamayı reddeder.
- Gözlemler otomatik olarak kötü amaçlı IP kanıtı sayılmaz. STIX gözlemleri ve kural skorları operatör incelemesi gerektirir.
- Güvenlik açığı bildirirken sentetik örnek kullanın ve kimlik bilgilerini paylaşmayın. Proje sahibi GitHub private vulnerability reporting özelliğini ayrıca etkinleştirebilir.

Yayın öncesinde güvenlik testlerini ve güncel bağımlılık taramasını tekrar çalıştırın. Testlerin geçmesi tüm açıkların yokluğunu kanıtlamaz.
