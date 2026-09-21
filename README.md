
## Быстрый запуск

Если файл уже находится на сервере:

```bash
sudo bash ./tfm.sh
```

После первой установки используйте:

```bash
sudo tfm.sh
```

## Запуск напрямую с GitHub

```bash
curl -fL https://raw.githubusercontent.com/Bangtott/tfm/main/tfm.sh -o ./tfm.sh && sudo bash ./tfm.sh
```

## Защита от потери SSH

Перед изменением firewall создаётся временная цепочка `TFM-SAFETY`. Она сохраняет доступ во время установки. Если установка завершается ошибкой, safety-правило остаётся активным и сохраняется через `netfilter-persistent`.

Скрипт не выполняет глобальный `iptables -F`, не меняет политики стандартных цепочек `INPUT`, `OUTPUT` и `FORWARD` и не использует `ufw reset`.

## Идемпотентность

Установщик управляет собственными цепочками `TFM-ACCESS`, `TFM-BLOCK`, `TFM6-ACCESS` и временной `TFM-SAFETY`.

Перед созданием jump-правил удаляются их прежние экземпляры, поэтому повторные применения не создают копии. Наборы блокировок обновляются атомарной заменой `ipset`.

## Требования

- Debian или Ubuntu;
- root-доступ;
- systemd;
- доступ к GitHub, `whois.radb.net` и репозиториям блок-листов;
- поддерживаемый системой backend `iptables`/`ip6tables`.

## Файлы после установки

| Путь | Назначение |
|---|---|
| `/usr/local/sbin/tfm.sh` | Интерактивное меню |
| `/usr/local/sbin/tfm-apply` | Применение сохранённых правил |
| `/usr/local/sbin/tfm-update-blocklists` | Обновление блок-листов |
| `/etc/traffic-firewall-manager.conf` | Конфигурация |
| `/etc/systemd/system/tfm-update.timer` | Расписание обновлений |
| `/etc/ipset.conf` | Сохранённые наборы `ipset` |

## Проверка после установки

```bash
sudo tfm.sh
sudo iptables -S TFM-ACCESS
sudo iptables -S TFM-BLOCK
sudo ip6tables -S TFM6-ACCESS
sudo ipset list -name
```

Перед применением на удалённом production-сервере рекомендуется оставить открытой вторую SSH-сессию или консоль провайдера.

фулл вайбкод хуйня братья