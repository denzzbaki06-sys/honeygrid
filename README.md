# Honeygrid

Java 21 tabanlı, HTTP tuzağı ve TCP bağlantı sensörü içeren bir güvenlik gözlem prototipi. Olaylar veritabanına kaydedilir ve kimliği doğrulanmış operatörlere WebSocket üzerinden gösterilir.

**Üretim seviyesinde CTI/SOAR ürünü değildir.** Kural tabanlı sınıflamalar gözlem ve tahmindir; saldırgan kimliğini veya zero-day açığını kanıtlamaz.

## Gerçek kapsam

| Özellik | Durum |
| --- | --- |
| HTTP sahte giriş sayfası, crawler tuzağı | Çalışır; girişler boyut ve istek sıklığı sınırına tabidir |
| TCP sensörü, varsayılan 2222 | Bağlantıyı kaydeder; tam SSH sunucusu değildir, SSH komutlarını toplamaz |
| Operatör paneli, canlı STOMP akışı | Oturum açma gerekir; saldırgan içerikleri metin olarak gösterilir |
| Payload sınıflaması / skor | Regex ve kurallar; LLM/AI çıkarımı değildir |
| H2 / PostgreSQL kayıtları | Yerelde dosya tabanlı H2; Docker'da PostgreSQL |
| YARA, PDF, STIX 2.1 | YARA tam UTF-8 payload eşleşmesi; PDF son 1000 olay; STIX gözlem verisi |
| Canary | Sahte dosya indirme ve önceden üretilmiş URL'ye istek tespiti; dosyayı açmak kendiliğinden beacon çağırmaz |
| Agent ingest | Ortamdan verilen API anahtarı ve doğrulanan JSON; boş anahtar ile kapalı |
| GeoIP / Dark Web / aktör atfı | Yapılandırılmış veri kaynağı yok; bilinmiyor olarak gösterilir |
| SOAR, firewall, memory dump, DNS sinkhole | Uygulanmamış; API 501 / NOT_IMPLEMENTED döner, işletim sistemini değiştirmez |
| PCAP, eBPF, sandbox çalıştırma | Uygulanmamış; sahte paket/işlem çıktısı üretilmez |
| Dağıtık node sağlık takibi | Uygulanmamış; node listesi boş |

## Yerelde başlatma

Java 21 gerekir. Wrapper Maven'i ilk kullanımda indirir.

```sh
./mvnw verify
./mvnw spring-boot:run
```

Panel: `http://localhost:8082/`. Kullanıcı: `operator`. `HONEYGRID_ADMIN_PASSWORD` verilmezse başlangıç logunda yalnızca bu çalıştırma için rastgele parola üretilir. Logu paylaşmayın. Kalıcı parola ortam değişkeniyle verilir ve en az 16 karakter olmalıdır.

HTTP ve TCP varsayılan olarak **127.0.0.1** üzerinde dinler. H2 kayıtları `data/` altındadır; yeniden başlatmada korunur. Varsayılan saklama süresi 30 gündür; eski olaylar saatte bir silinir.

Tamamen yerel bir deneme:

```sh
curl -i -X POST http://localhost:8082/admin-login -d 'username=demo&password=synthetic-example'
```

Sahte girişin 401 dönmesi normaldir; olay açık operatör paneline düşer. Gerçek parolanızı bu forma yazmayın.

## Docker / PostgreSQL

```sh
cp .env.example .env
# .env içine kendi HONEYGRID_ADMIN_PASSWORD ve HONEYGRID_DB_PASSWORD değerlerinizi yazın.
# Rastgele değer üretmek için: openssl rand -hex 24
# Agent kullanacaksanız HONEYGRID_AGENT_API_KEY için en az 32 karakter verin.
docker compose up --build -d
```

8082 ve 2222 yalnızca host loopback adresinde yayımlanır. PostgreSQL dışarıya port açmaz; healthcheck başarılı olmadan uygulama başlamaz. Uygulama konteyneri root olmayan kullanıcıyla çalışır; OS firewall yetkisi verilmez.

`.env` Compose içindir; `./mvnw spring-boot:run` bu dosyayı otomatik yüklemez. Java ile başlatırken değerleri ortam değişkeni olarak sağlayın.

## Yapılandırma

| Değişken | Varsayılan / anlam |
| --- | --- |
| `HONEYGRID_ADMIN_USERNAME` | `operator` |
| `HONEYGRID_ADMIN_PASSWORD` | Yoksa geçici rastgele parola; verilirse en az 16 karakter |
| `HONEYGRID_AGENT_API_KEY` | Boşsa agent ingest kapalı; en az 32 karakter |
| `PORT` | 8082 |
| `HONEYGRID_BIND_ADDRESS` | 127.0.0.1 |
| `HONEYGRID_SSH_ENABLED` | true |
| `HONEYGRID_SSH_BIND_ADDRESS` | 127.0.0.1 |
| `HONEYGRID_SSH_PORT` | 2222; kullanımdaysa başlangıç başarısız olur |
| `HONEYGRID_CANARY_BASE_URL` | http://localhost:8082; uzak sensörde erişilebilir kendi URL'nizi verin |
| `HONEYGRID_RETENTION_DAYS` | 30; 1–3650 |
| `SPRING_DATASOURCE_URL` | Dosya tabanlı H2; PostgreSQL URL'si verilirse JDBC sürücüsü otomatik seçilir |
| `SPRING_DATASOURCE_USERNAME` / `SPRING_DATASOURCE_PASSWORD` | Harici veritabanı kimlik bilgileri |

Uzak dağıtımda HTTPS, ağ erişim politikası, güvenilir reverse proxy ve yönetim/sensör uçlarının ağ seviyesinde ayrılması gerekir. Bu depo otomatik bir internet dağıtımı sağlamaz. Forwarded IP başlıklarına güvenilmez; reverse proxy arkasında kaynak IP proxy olabilir. Veriler gerçek payload içerebilir; retention ve erişim politikasını buna göre belirleyin.

## API davranışı

- Yönetim API'leri operatör oturumu ister. Değişiklik yapan operatör POST'ları `/api/session/csrf` token'ını gerektirir.
- `/api/v1/agent/ingest`: `X-Agent-API-Key` ile POST. Alanlar: `ipAddress` (IP literal), `port` (1–65535), `protocol` (büyük harf/rakam/alt çizgi, en fazla 40 karakter), `payload` (en fazla 2000 karakter). IP, tek başına gerçek kaynak kimliğini kanıtlamaz.
- İstek boyutu 16 KiB ile sınırlıdır. HTTP sensör/agent/login uçlarında kaynak adres başına dakikada 120 istek sınırı vardır. Bu basit yerel sınır dağıtık DDoS koruması değildir.
- `/api/v1/threat-intel/export/stix2?page=0` ve `/export/plain-ips?page=0`: sayfa başına 1000 kayıt, ID sırası; sonraki sayfalar için `page` artırılır. IP listesi gözlem listesidir, otomatik firewall blacklist'i değildir.
- PDF ve ilişki grafiği en güncel 1000 olayla sınırlıdır; grafikte `truncated` bilgisi vardır.
- Panel sayaçları açık tarayıcı oturumunu gösterir; olay listesi son 300 satırı tutar. GeoIP kaynağı olmadığı için küre üzerinde konum uydurulmaz.
- Canary token'ları RAM'de en fazla 24 saat / 10.000 token tutulur ve yeniden başlatmada kaybolur.

## Testler

```sh
./mvnw verify
node --test src/test/js/event-view.test.cjs
```

Java testleri kimlik doğrulama, rol, CSRF, agent doğrulama, export, SOAR durumları, YARA, canary ve TCP dinleyici hata yollarını kapsar. Panel testleri XSS payload'ının metin olarak kalmasını ve DOM boyut sınırını kontrol eder. CI aynı komutları çalıştırır.

WebGL paneli sabit sürümlü CDN kütüphaneleri ve harici küre dokuları kullanır; internet/CDN erişimi gerektirir. Offline asset paketi bu sürümde yoktur.

## GitHub'a hazırlık

`.env`, `data/`, trafik kayıtları, dump'lar ve `target/` depoya alınmamalıdır. `.env.example` yalnızca boş alanlar içerir. `.gitignore`, önceden commit edilmiş bir dosyayı geçmişten kaldırmaz. Eski `pcap_dumps/` ve `env-config` içeren geçmişi yayımlamayın; temiz kaynak paketinden yeni bir Git geçmişi başlatın veya önce geçmiş temizliğini ayrıca planlayın. Mevcut uzak deponun geçmişi bu düzeltme sırasında değiştirilmemiştir.

Spring Boot 3.5.16, eski 3.2.5 sürümünün yerine kullanılır. Güvenlik düzeltmeleri için Jackson 2.21.5, Log4j 2.25.5, Tomcat 10.1.59 ve PostgreSQL JDBC 42.7.12 sabitlenmiştir. 3.x hattında kalmak bu düzeltmenin uyumluluk sınırıdır; internet üretimi için desteklenen sürüm hattına geçiş ve bağımlılık güvenlik taraması ayrıca değerlendirilmelidir. [3.5.16 sürüm duyurusu](https://spring.io/blog/2026/06/25/spring-boot-3-5-16-available-now/)

PDF için iText 5 kullanılır. Dağıtım öncesinde iText'in AGPL/ticari lisans şartlarını kendi kullanımınıza göre değerlendirin. Bu depoya proje sahibi adına yeni bir lisans atanmadı.
