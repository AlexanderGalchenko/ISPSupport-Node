# ISP Support Node

## Изолированные PPPoE-сессии

`scripts/pppoe.py` управляет тестовыми каналами ноды. Для каждого профиля создаётся
network namespace `isp-pppoe-<profile>` со своими маршрутами и DNS. Выделенная
Ethernet NIC переносится туда целиком с сохранением MAC. Интерфейс с глобальным
IP, маршрутом, master/child-связью или сетевым менеджером не используется.
Проверки: IPv4 ping, DNS, HTTPS www.yandex.ru и ICMP с DF для MTU.

Установка отдельно от обновления Git, от root:

```sh
bash /ispsupport/node/scripts/install-pppoe.sh
```

Локальный профиль `/etc/ispsupport-node/pppoe/lab.json` (root:root 600), пример
с вымышленными адресами:

```json
{
  "schema": 1,
  "interface": "eth1",
  "expected_mac": "02:00:00:00:00:01",
  "bras_label": "lab",
  "bras_address": "192.0.2.10",
  "bras_port": "et-0/0/0.123",
  "transport_vlan": 123,
  "vlan": null,
  "ac": "LAB_AC",
  "env_file": "/etc/ispsupport-node/pppoe/lab.env",
  "ping": ["8.8.4.4", "8.8.8.8", "77.88.8.8"],
  "skip_initial_tests": false
}
```

`vlan: null` означает нетегированный Ethernet **внутри гостя**. `transport_vlan`
документирует внешний транспорт и не добавляет тег в госте. Опциональные `device_id`,
`expected_ac_mac` и `note` уточняют привязку. IP/порт BRAS — запись инвентаризации,
не доказательство фактического подключения к этому порту. `expected_ac_mac`
сравнивается с наблюдаемым AC в status, но не является фильтром PPPoE.

В `/etc/ispsupport-node/pppoe/lab.env` (root:root 600) задаются `PPPOE_USERNAME`
и `PPPOE_PASSWORD`. Значения литеральные, файл не исполняется оболочкой;
пароль не передаётся в argv дочерних процессов. Профили и секреты не коммитятся.

```sh
ispsupport-pppoe check lab     # предварительная проверка без изменения сети
ispsupport-pppoe start lab     # подключение, первый тест, затем удержание
ispsupport-pppoe status lab    # JSON: привязка, systemd, состояние и результаты
ispsupport-pppoe probe lab     # запрос тестов в существующей сессии
ispsupport-pppoe schedule lab  # проверки каждые 5 минут
ispsupport-pppoe quiet lab     # отключить таймер, сохранить сессию
ispsupport-pppoe stop lab      # отключить таймер, завершить PPP, вернуть NIC
```

`probe` асинхронный: результат появится в `last_test` после завершения проверок.
Занятая/ещё не поднятая/завершённая сессия пропускается, не запускается заново.
`Restart=no`, `nopersist` и отсутствие автоматического старта сессии после reboot
позволяют наблюдать отключения от биллинга. После отключения нужен явный `start`.
Для старта без первого раунда трафика задайте `skip_initial_tests: true`.
В тихом режиме остаются LCP keepalive и локальное наблюдение раз в 5 секунд.
Ping/HTTPS не измеряют тарифную скорость и не подтверждают применение RADIUS CoA;
нужны данные с BRAS и отдельный согласованный тест скорости.

Отчёты: `/var/lib/ispsupport-node/pppoe/<profile>/current.json` указывает на run;
`runs/<run-id>/` содержит `result.json`, `probe-*.json`, `events.jsonl`, приватный
`pppd.log`, снимки интерфейса/маршрутов и `RECOVERY.txt`. Сохраняются привязка
и Git revision каждого запуска. Старые отчёты автоматически не удаляются.
Логи закрыты для других пользователей и могут содержать логин.
Диагностика: `journalctl -u ispsupport-pppoe@lab -n 80 --no-pager`.

Для диагностики переговоров установите в локальном профиле `capture_control: true`
перед следующим подключением (нужен `tcpdump`). Дамп `ppp-control.pcap` снимается
в namespace до запуска pppd, максимум 75 секунд/1000 пакетов. Фильтр ограничен
MAC тестового клиента, PPPoE Discovery, LCP/IPCP/IPv6CP и результатами аутентификации;
PAP-запросы, CHAP challenge/response и пользовательский IP-трафик исключены.
Просмотр от root: `tcpdump -nn -e -tttt -vvv -r /path/to/run/ppp-control.pcap`.
После диагностики верните `capture_control: false`. Глобальный debug BRAS не нужен.

Обычная остановка возвращает NIC, сверяет маршруты/rules/DNS хоста и сохраняет
`cleanup_ok`. При SIGKILL/падении питания следуйте `RECOVERY.txt`; не удаляйте
namespace до завершения оставшихся процессов. Для отката остановите профиль,
проверьте `cleanup_ok`, восстановите unit/CLI из `install-backup-*` в каталоге
состояния и выполните `systemctl daemon-reload`. Код откатывается revert-коммитом
через штатное fast-forward обновление, без сброса рабочей копии.
Обновление Git и повторная установка не перезапускают поднятые сессии.

Базовый репозиторий клиентских нод ISP Support.

## Размещение
- Код: `/ispsupport/node/`
- Локальная конфигурация: `/etc/ispsupport-node/node.json`
- Результат обновления: `/var/lib/ispsupport-node/update.json`
- Обновления: systemd timer `ispsupport-node-update.timer`, один раз в час.

Все административные SSH-подключения к нодам выполняются с основной машины ISP Support.
Одна компания может иметь несколько нод и несколько операторов; привязки задаются в основной системе.

В этом публичном репозитории нельзя хранить адреса клиентских узлов, ключи, токены, конфигурации клиентов или базы данных.
Пока репозиторий содержит только основу установки и обновления. Мониторинг, локальная БД и API будут добавляться отдельными выпусками.

## Установка на новую ноду

Выполнить через SSH с основной машины, после добавления её ключа в authorized_keys ноды:

```sh
git clone --branch main https://github.com/AlexanderGalchenko/ISPSupport-Node.git /ispsupport/node
bash /ispsupport/node/scripts/install.sh
```

Нужны Ubuntu/Debian с systemd, Git, Python 3 и исходящий HTTPS-доступ к GitHub.
Основная машина сохраняет настройки компании и операторов в /etc/ispsupport-node/node.json.
Не редактируйте рабочую копию кода на ноде: изменения вносятся в этот репозиторий.

## Проверка

```sh
systemctl list-timers ispsupport-node-update.timer
journalctl -u ispsupport-node-update.service -n 30
cat /var/lib/ispsupport-node/update.json
```

Проверка выполняется каждый час с задержкой до 120 секунд. Для немедленной проверки можно запустить `systemctl start ispsupport-node-update.service`.
Обновление допускает только fast-forward. Ошибка сети, локальные изменения или расхождение истории останавливают обновление; локальная конфигурация и данные остаются на месте.
Таймер обновляет файлы репозитория. Запуск сервисов и миграции будущего приложения должны быть добавлены отдельным выпуском.


## Device checks

### LLDP topology

`scripts/lldp_collect.py` collects local LLDP identity and neighbor tables over SSH
from explicitly configured Junos and Huawei VRP devices. It uses the existing
limited account and node keys. Commands are read-only; discovered neighbors are
not automatically scanned or added to inventory. Junos uses XML; Huawei uses
bounded, prompt-checked CLI output. Numeric remote port IDs are retained for
resolution against the neighbor's local LLDP table.

The Main gateway includes cached snapshots in telemetry. Successful snapshots
are refreshed after 10 minutes; failed attempts after 3 minutes, with at most
four concurrent collections per gateway batch. Cache files in
`/var/lib/ispsupport-node/lldp/` are private to root. Main retains the last
successful table on collection failure and marks it stale; a successful empty
table removes previous observations. Multiple neighbors on one port are marked
as observations of a shared segment rather than confirmed direct cables.

For a manual collection of up to four due devices, run on the node:

```sh
python3 /ispsupport/node/scripts/lldp_collect.py --force
```

This prints operational topology data; keep it outside the public repository.

The primary gateway supplies an explicit device batch through its SSH connection to the node. `scripts/monitor.py` runs ICMP, public-key SSH (`show version | no-more` for Junos), and SNMP v2c system OID checks on the node. The primary application does not connect to equipment. Devices with monitoring disabled are excluded from batches. Network inventory never triggers subnet scanning.

SSH uses the node root account's existing private keys with a limited equipment username; equipment username `root` is rejected. First-seen device host keys are stored in `/var/lib/ispsupport-node/device_known_hosts`; changed host keys stop authentication. SNMP requires the `snmp` client package, installed by `scripts/install.sh`; no SNMP daemon is installed. Community values are read from a temporary mode-0600 file and are never passed in process arguments. Client configuration and credentials remain outside this repository.

The initial gateway selects up to 20 enabled devices per node every five minutes, oldest check first, using eight bounded concurrent workers. This is a basic availability/access check, not interface traffic collection or alerting. After setting credentials and firewall rules, enable polling in the device card.
