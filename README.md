# OURs
### OURs - web инструмент для скана устройств в сети и брута ssh ftp



#  Запуск бекенда:
   cd back
   
   <h3>pip3 install -r requirements.txt</h3>
   Для работы необходимы root права
   <h3>sudo python3 scaner_api.py</h3>

#  Запуск фронта:
   <h3>http-server dist -p 5173 --push-state</h3>
   
   dev:    npm i run dev
           npm run build
      
         

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/0a63526e-764d-4511-8de2-d55366fd4514" alt="qr"/>
</p>

<h3>Для запуска сканирования необходимо ввести адрес подсети который вы хотите просканировать</h3>
Например: <i>192.168.1.0/24</i>
Нажать "Начать сканирование"

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/9cea0e32-6535-43e6-a8df-2fd083eb8281" alt="qr"/>
</p>

<h3>Далее выберите из списка найденное устройство и начните сканирование портов</h3>


<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/f6bae41d-0002-4f8d-93ba-8d07f148b18a" alt="qr"/>
</p>

<h3>Отобразиться список портов, и если среди них есть ftp (включая проверку на анонимного пользователя) или ssh то появиться опция "Запустить FTP/SSH брут"<br>После завершения при успешном сканировании появятся подобранные учетные данные от SSH/FTP</h3>

<p align="center">
   <img width="100%" src="https://github.com/user-attachments/assets/cd2e818b-3787-4211-8663-e19e557f72c0" alt="qr"/>
</p>



