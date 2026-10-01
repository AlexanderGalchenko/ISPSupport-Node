# ISP Support Node

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

The primary gateway supplies an explicit device batch through its SSH connection to the node. `scripts/monitor.py` runs ICMP, public-key SSH (`show version | no-more` for Junos), and SNMP v2c system OID checks on the node. The primary application does not connect to equipment. Devices with monitoring disabled are excluded from batches. Network inventory never triggers subnet scanning.

SSH uses the node root account's existing private keys with a limited equipment username; equipment username `root` is rejected. First-seen device host keys are stored in `/var/lib/ispsupport-node/device_known_hosts`; changed host keys stop authentication. SNMP requires the `snmp` client package, installed by `scripts/install.sh`; no SNMP daemon is installed. Community values are read from a temporary mode-0600 file and are never passed in process arguments. Client configuration and credentials remain outside this repository.

The initial gateway selects up to 20 enabled devices per node every five minutes, oldest check first, using eight bounded concurrent workers. This is a basic availability/access check, not interface traffic collection or alerting. After setting credentials and firewall rules, enable polling in the device card.
