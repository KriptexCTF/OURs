# OURs

----

OURs - web-инструмент для сканирования активов в сети. Проведения брутфорс-атак на сервисы: ssh, ftp. Фаззинга директорий веб приложения. Поиска известных уфзвимостей сервисов, с помощью утилиты SearchSploit

#### Инструмент требует предустановленных в системе утилит:
- [Nmap](https://nmap.org/docs.html)
- [SearchSploit](https://gitlab.com/exploit-database/exploitdb)

----

#### Для настройки параметров работы бекенда используется файл [config.ini](back/config.ini)
```
[General]
threads = 20
; Set the log level <debug>. Options: 'critical', 'error', 'warning', 'info', 'debug', 'trace'
debug = debug
host = 127.0.0.1
port = 8081

[Path]
password_list = ./wordlists/passwordListTop100.txt
username_list = ./wordlists/usernamesList.txt
oui_file = ./lib/oui/oui_latest.json

[Web]
dir_fuzz_list = ./wordlists/fuzz_dir_copy.txt

[Nmap]
scan_parametrs = "-sS -sV -T5"
```
----

## Using




         

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/7a94e4be-1606-42c6-b685-795171445e15" alt="qr"/>
</p>

<br>

## Для запуска сканирования необходимо ввести любой ip-адрес из подсети, указав маску сети в формате CIDR
#### Например: ``` 192.168.1.0/24 ```<br>Нажать "Начать сканирование"

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/1a5f41e3-42f9-468b-96f3-544fcff99634" alt="qr"/>
</p>

<h3>Из списка найденных устройств выберите необходимое и начните сканирование портов "Скан портов"</h3>

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/c09f9c1f-159c-49ad-9c3b-7a6bd5410fc9" alt="qr"/>
</p>

<img width="100%" src="https://github.com/user-attachments/assets/7f9a155a-e1ca-40ac-9131-312576339ed9" alt="qr"/>

<br>

## Брутфорс
#### После сканирования портов отобразиться список открытых, если среди них есть ftp или ssh то появиться опция "Запустить FTP/SSH брут" (включая проверку на анонимного пользователя)<br>После завершения в случае успеха появятся подобранные учетные данные от SSH/FTP

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/888d4d71-0d19-4739-a66f-a41662bfa395" alt="qr"/>
</p>

<br>

----

# Installation
###  Запуск бекенда (папка back):
   Необходимо установить зависимые библиотеки, файл [requirements.txt](back/requirements.txt)<br>
   ```pip3 install -r requirements.txt```<br>
   После установки зависимостей запустите [scaner_api.py](back/scaner_api.py)
   #### ```sudo python3 scaner_api.py```
   Для работы бекенда необходимы root права
<p align="left">
   <img width="50%" src="https://github.com/user-attachments/assets/a088cf1c-d817-4ef3-8617-dd5c9b72218a" alt="qr"/>
</p>

----

###  Запуск фронта (папка front):
   #### ```http-server dist -p 5173 --push-state```

<br>

##### Установка зависимостей и запуск режима разработчика
```   
npm i run dev
```
##### Сборка
```
npm run build
```

----
