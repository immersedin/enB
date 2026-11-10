# P2P Secure Chat

Децентрализованный E2EE-мессенджер на C++20 (CLI/TUI). Без центральных
серверов: идентичность, поиск собеседников и передача сообщений работают
напрямую между устройствами.

## Архитектура

```
                    ┌─────────────────────────────┐
                    │        Kademlia DHT         │
                    │   (UDP, peer records)       │
                    └──────────────┬──────────────┘
                                   │ FIND_VALUE(peer_id)
                                   ▼
   ┌──────────┐   invite / peer id   ┌──────────┐
   │  Peer A  │◄────────────────────►│  Peer B  │
   │ Identity │   TCP + Noise XX     │ Identity │
   │  Ed25519 │   + Double Ratchet   │  Ed25519 │
   └──────────┘   (E2EE канал)       └──────────┘
```

- **Peer ID** — hex от X25519-публичного ключа (64 символа). Тот же ключ
  является статическим ключом Noise, поэтому личность в DHT и на
  проводе доказуема одним handshake'ом.
- **Идентичность**: X25519 (DH) + Ed25519 (подписи). Ключи лежат в
  `~/.p2p-chat/*.key` с правами 0600, приватный ключ никуда не
  передаётся.
- **DHT** (`src/dht.cpp`): Kademlia поверх UDP — k-buckets (k=20),
  FIND_NODE / FIND_VALUE / STORE / PING, итеративные lookup'ы (α=3).
  Peer-запись — подписанный Ed25519 blob: peer_id, имя, список TCP
  endpoint'ов чата. Подпись делает запись неподделываемой;Noise-handshake
  затем доказывает владение приватным X25519-ключом.
- **NAT discovery**: каждый DHT-ответ несёт `observed_ep` — адрес
  отправителя, как его видит пир. Публичный IP изучается без
  центрального сервера и публикуется вместе с chat-портом.
- **E2EE**: Noise_XX_25519_ChaChaPoly_SHA256 (взаимная аутентификация,
  forward secrecy) + Double Ratchet поверх — per-message X25519 DH.
- **Хранение**: SQLCipher (SQLite) для контактов и истории.

## Сборка

Зависимости (macOS): `brew install asio libsodium sqlcipher ftxui`
Windows: `vcpkg install asio libsodium sqlcipher ftxui`

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Использование

```bash
p2p
```

Команды внутри TUI:

| Команда | Назначение |
|---|---|
| `/peerid` | показать свой Peer ID и DHT endpoint (копируется в буфер обмена) |
| `/invite [ttl] [save <file>]` | создать подписанное приглашение (TTL сек, по умолчанию 300); код копируется в буфер обмена |
| `/connect <code\|peer-id\|name>` | принять приглашение / подключиться по Peer ID / по имени |
| `/copyid <name>` | скопировать Peer ID контакта в буфер обмена |
| `/friends` | контакты со статусом online/offline и Peer ID |
| `/bootstrap <host:port>` | добавить DHT bootstrap-узел (сохраняется в config.ini) |
| `/dht` | статистика DHT (известные узлы, записи, observed endpoint) |
| `/add <name> <host> <port>` | ручное добавление по адресу (fallback) |
| `/chat <name>`, `/close`, `/quit` | как раньше |

Прокрутка консоли и чата: `PgUp`/`PgDn`, стрелки ↑/↓ или колесо мыши.

### Типичный сценарий

```
# A:                                    # B:
/invite                                  /connect <код-от-A>
# → Peer ID + код, передать B любым каналом   → резолвит peer record через DHT,
                                              проверяет подпись, коннектится
```

Повторное подключение: `/connect <peer-id>` — приложение ищет
актуальные адреса через DHT и проверяет, что удалённый Noise static key
совпадает с Peer ID. Смена Ed25519-ключа собеседника вызывает WARNING и
отказ в соединении (а не молчаливое принятие).

### Конфигурация (`~/.p2p-chat/config.ini`)

```
port=5555          # TCP chat + UDP DHT (можно разделить: dht_port=)
dht_port=0         # 0 = тот же номер, что и port
dht_port=5556
name=alice
bootstrap=1.2.3.4:5555     # можно несколько строк
```

## Self-test

```bash
p2p --selftest
```

Поднимает 3 реальных Kademlia-узла и 2 Net-инстанса на loopback:
bootstrap, многошаговый FIND_VALUE, подписанные peer-записи, полный
Noise XX + Double Ratchet обмен сообщением, отказ при подмене peer id и
при смене ed25519-ключа, приглашения (включая tamper/expiry). Без моков.

## Ограничения (честно)

- **Bootstrap обязателен для первого входа**: новый узел не может найти
  сеть из ничего — нужен хотя бы один известный peer (через `/bootstrap`,
  `bootstrap=` в config.ini или DHT-hint внутри приглашения). Архитектура
  не зависит от конкретного узла: любой участник сети может быть
  bootstrap.
- **DHT — не глобальный каталог**: запись живёт на k ближайших узлах и
  реплицируется; при массовом оттоке сети или сплите поиск может не
  найти peer, даже если тот онлайн. Это свойство Kademlia, не баг.
- **NAT**: при symmetric NAT / строгом firewall прямое TCP-соединение
  может не установиться. Реализовано best-effort: публикация observed
  public endpoint (full-cone NAT), параллельный dial всех известных
  адресов, fallback на последний рабочий endpoint. UDP hole punching и
  Circuit Relay v2 **не реализованы** — relay не является обязательным
  компонентом, но и не гарантирует связность при жёстком NAT.
- **QUIC не используется**: транспорт — TCP. QUIC дал бы 0-RTT и
  миграцию соединения при смене IP, но требует отдельного стека
  (quiche/msquic) без выигрыша в криптостойкости — Noise уже даёт E2EE.
  При смене IP peer переподключается через DHT-resolved адреса.
- **Нет гарантий при частичной недоступности DHT**: lookup
  итеративный и отказоустойчивый (таймауты, α-параллелизм), но при
  < k живых узлах результат зависит от топологии.

## Структура

```
src/crypto.*    Noise_XX, Double Ratchet, Ed25519, HKDF (libsodium)
src/net.*       TCP транспорт, сессии, peer-id проверка, key-change detection
src/dht.*       Kademlia UDP node, routing table, signed peer records
src/invite.*    приглашения (Ed25519-signed, base64url, TTL)
src/endpoint.*  IPv4/IPv6 endpoint codec + local address enumeration
src/db.*        SQLCipher хранение контактов и истории
src/selftest.*  headless интеграционный тест (--selftest)
src/update.*    автообновление через GitHub Releases
src/main.cpp    FTXUI CLI + slash-команды
```
