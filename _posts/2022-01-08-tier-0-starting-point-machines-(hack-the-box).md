---
title: Tier 0 Starting Point Machines (Hack The Box)
author: J0lm3d0
date: 2022-01-08 19:00:00 +0200
categories: [HackTheBox]
tags: [linux, windows, default_credentials, noob]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de las máquinas de Tier 0 del "Starting Point" de la plataforma HackTheBox. Se trata de máquinas tanto Windows como Linux, que tienen una dificultad muy fácil de resolución y están orientadas a la gente que está en proceso de aprendizaje de técnicas básicas de explotación.

## MÁQUINA MEOW

### Enumeración de servicios y recopilación de información sensible

Lo primero a realizar normalmente en la resolución de una máquina es un escaneo de todo el rango de puertos TCP. La herramienta más utilizada para ello es `Nmap`, ya que cuenta con multitud de funciones y es muy potente. Aunque existen otras herramientas similares que nos ayudarán a identificar los puertos abiertos o, incluso podríamos crearlas nosotros de forma relativamente sencilla.

Para realizar un escaneo de todos los puertos, empleo la flag -p-, que sería una forma abreviada de -p1-65535. Por otra parte, utilizo también la flag -v de forma doble, es decir, -vv, para indicar que quiero más detalle en el resultado indicado y que me vaya reportando los puertos abiertos conforme los vaya descubriendo. Por último, empleo la flag -T5, esta flag hace referencia al tiempo que tarda el escaneo y su valor puede establecerse entre 0 (más lento) y 5 (más rapido). Al estar en un entorno controlado como es HackTheBox, no habría ningún problema en establecer el tiempo más rápido, ya que, aunque es más agresivo, también hará que el escaneo finalice mucho antes.

```
# nmap -p- -T5 -vv 10.129.229.82

Not shown: 63411 closed tcp ports (conn-refused), 2123 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack
```

Tras obtener los puertos que la máquina tiene abiertos, lo que suelo hacer es utilizar de nuevo *Nmap* para aplicar algunos scripts básicos NSE (Nmap Scripting Engine), que se encargan de enumerar información (flag -sC) e intentar descubrir la versión y servicio (flag -sV) que están ejecutando los puertos abiertos.

```
# nmap -p23 -sCV 10.129.229.82

PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Acceso a la máquina

Solo encuentro el puerto 23 de [Telnet (Teletype Network)](https://es.wikipedia.org/wiki/Telnet) abierto. Telnet es un protocolo de red que nos permite acceder a otra máquina para manejarla remotamente en modo terminal. Su mayor problema, y por el que apenas se usa hoy en día, es que toda la comunicación se realiza en texto claro, incluido el login, por lo que un atacarte podría obtener las credenciales si estuviese interceptando el tráfico de la conexión.

En este caso, al contar con este solo puerto abierto, no hay mucho más por donde tirar, por lo que lo primero a probar será intentar acceder con usuarios y credenciales por defecto. Como no tengo recopilado ningún usuario existente en la máquina, pruebo a conectarme con el usuario root, que es el usuario administrador que siempre encontraremos por defecto en sistemas Unix:

![Conexión por telnet a la máquina](/assets/img/HTB/Meow/telnet.png)

Como se ve en la imagen, debido a un error o a una falta de configuración, no me ha solicitado contraseña alguna para acceder a la máquina. Por tanto, ya me encuentro conectado al objetivo con permisos de superusuario y puedo visualizar la flag, completando así la resolución de la máquina.

![Flag de la máquina Meow](/assets/img/HTB/Meow/flag.png)

### Cuestionario

1. *What does the acronym VM stand for?* (¿Qué significan las siglas MV?)

    Virtual Machine (Máquina Virtual)

2. *What tool do we use to interact with the operating system in order to start our VPN connection?* (¿Qué herramienta utilizamos para interactuar con el sistema operativo con el fin de iniciar nuestra conexión VPN?)

    terminal

3. *What service do we use to form our VPN connection?* (¿Qué servicio utilizamos para formar nuestra conexión VPN?)

    OpenVPN

4. *What is the abreviated name for a tunnel interface in the output of your VPN boot-up sequence output?* (¿Cuál es el nombre abreviado de una interfaz de túnel en la salida de la secuencia de inicio de VPN?)

    tun

5. *What tool do we use to test our connection to the target?* (¿Qué herramienta usamos para probar nuestra conexión con el objetivo?)

    ping

6. *What is the name of the script we use to scan the target's ports?* (¿Cuál es el nombre del script que usamos para escanear los puertos del objetivo?)

    Nmap

7. *What service do we identify on port 23/tcp during our scans?* (¿Qué servicio identificamos en el puerto 23 de TCP durante nuestros escaneos?)

    Telnet

8. *What username ultimately works with the remote management login prompt for the target?* (¿Qué nombre de usuario funciona en última instancia con la solicitud de inicio de sesión para la gestión remota del destino?)

    root

## MÁQUINA FAWN

### Enumeración de servicios y recopilación de información sensible

Realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.131.200

Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
```

Una vez obtengo los puertos que la máquina tiene abiertos, utilizo las flags -sC y -sV para aplicar scripts básicos de enumeración e intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p21 -sCV 10.129.131.200

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.15.235
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
Service Info: OS: Unix
```

Solo se encuentra el puerto 21 de [FTP (File Transfer Protocol)](https://es.wikipedia.org/wiki/Protocolo_de_transferencia_de_archivos) abierto. FTP es un protocolo de red que permite la transferencia de archivos entre un cliente y un servidor. El cliente se conecta al servidor y tiene la capacidad de descargar los archivos compartidos por el servidor o envíar archivos de su equipo al servidor. Su mayor problema es la seguridad, ya que al igual que Telnet realiza toda la comunicación en texto plano, pudiendo interceptar tanto credenciales como el contenido de ciertos archivos, que podría ser sensible.

Como muestra el segundo escaneo de *Nmap*, el login anónimo está permitido. Esto es una opción que podemos habilitar al configurar el servidor FTP, y que permite el login con el usuario "anonymous" sin validación de contraseña (podemos poner cualquier cosa o dejarla en blanco). Por tanto, me conecto con dicho usuario y, como también se observaba en el escaneo, en el directorio remoto se encuentra el archivo de texto con la flag, que procedo a descargar con el comando *get* para visualizarla en mi máquina ofensiva, completando así el desafío.

![Flag de la máquina Fawn](/assets/img/HTB/Fawn/flag.png)

### Cuestionario

1. *What does the 3-letter acronym FTP stand for?* (¿Qué significa el acrónimo de 3 letras FTP?)

    File Transfer Protocol (Protocolo de transferencia de archivos)

2. *What communication model does FTP use, architecturally speaking?* (¿Qué modelo de comunicación utiliza FTP, arquitectónicamente hablando?)

    Client-server model (Modelo cliente-servidor)

3. *What is the name of one popular GUI FTP program?* (¿Cuál es el nombre de un popular programa de FTP con interfaz gráfica de usuario?)

    Filezilla

4. *Which port is the FTP service active on usually?* (¿En qué puerto suele estar activo el servicio FTP?)

    21 tcp

5. *What acronym is used for the secure version of FTP?* (¿Que acrónimo es utilizado para la versión segura de FTP?)

    SFTP

6. *What is the command we can use to test our connection to the target?* (¿Cuál es el comando que podemos usar para probar nuestra conexión al objetivo?)

    ping

7. *From your scans, what version is FTP running on the target?* (De los resultados de tus escaneos, ¿que versión de FTP se está ejecutando en el objetivo?)

    vsftpd 3.0.3

8. *From your scans, what OS type is running on the target?* (De los resultados de tus escaneos, ¿que tipo de sistema operativo se está ejecutando en el objetivo?)

    Unix

## MÁQUINA DANCING

### Enumeración de servicios y recopilación de información sensible

Escaneo todo el rango de puertos TCP utilizando la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.135.203

Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
```

Una vez obtengo los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración e intento conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 -sCV 10.129.135.203

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4h10m20s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-12-13T20:32:47
|_  start_date: N/A
```

Detecto varios puertos abiertos, pero en esta situación lo mejor es comenzar por el puerto 445 de [SMB (Server Message Block)](https://es.wikipedia.org/wiki/Server_Message_Block). SMB es un protocolo de red que permite compartir archivos, impresoras, etc., entre nodos de una red de computadores que usan el sistema operativo Microsoft Windows.

Lo primero a intentar, es listar los recursos compartidos y ver si se puede acceder a alguno/s de ellos mediante una sesión nula, es decir, sin proporcionar usuario ni contraseña. Empleando la herramienta `SMBClient` logro conectarme y veo un recurso compartido "WorkShares". Intento acceder a este recurso compartido mediante una sesión nula y tengo éxito, por lo que listo el contenido de dicho recurso y encuentro la flag en el directorio de "James.P". Una vez encontrada la flag, la situación sería similar a la máquina anterior con el protocolo FTP: procedo a descargarla utilizando el comando *get* y la visualizo en mi equipo.

![Flag de la máquina Dancing](/assets/img/HTB/Dancing/flag.png)

### Cuestionario

1. *What does the 3-letter acronym SMB stand for?* (¿Qué significa el acrónimo de 3 letras SMB?)

    Server Message Block

2. *What port does SMB use to operate at?* (¿En qué puerto suele operar SMB?)

    445

3. *What network communication model does SMB use, architecturally speaking?* (¿Qué modelo de comunicación de red utiliza SMB, arquitectónicamente hablando?)

    Client-server model (Modelo cliente-servidor)

4. *What is the service name for port 445 that came up in our nmap scan?* (¿Cuál es el nombre del servicio para el puerto 445 que aparece en nuestro escaneo de nmap?)

    microsoft-ds

5. *What is the tool we use to connect to SMB shares from our Linux distribution?* (¿Cuál es la herramienta que utilizamos para conectarnos a los recuersos compartidos por SMB desde nuestra distribución de Linux?)

    smbclient

6. *What is the "flag" or "switch" we can use with the SMB tool to list the contents of the share?* (¿Cuál es la "flag" o "switch" que podemos utilizar con la herramienta de SMB para listar los recursos compartidos?)

    -L

7. *What is the name of the share we are able to access in the end?* (¿Cuál es el nombre del recurso compartido al que somos capaces de acceder finalmente?)

    WorkShares

8. *What is the command we can use within the SMB shell to download the files we find?* (¿Cuál es el comando que podemos usar dentro de la consola de SMB para descargar los archivos que encontramos?)

    get

## MÁQUINA EXPLOSION

### Enumeración de servicios y recopilación de información sensible

Realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.205.35

Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
5985/tcp  open  wsman         syn-ack ttl 127
47001/tcp open  winrm         syn-ack ttl 127
49664/tcp open  unknown       syn-ack ttl 127
49665/tcp open  unknown       syn-ack ttl 127
49666/tcp open  unknown       syn-ack ttl 127
49667/tcp open  unknown       syn-ack ttl 127
49668/tcp open  unknown       syn-ack ttl 127
49669/tcp open  unknown       syn-ack ttl 127
49670/tcp open  unknown       syn-ack ttl 127
49671/tcp open  unknown       syn-ack ttl 127
```

Tras este primer escaneo, aplico scripts básicos de enumeración e identifico la versión y servicio que están ejecutando cada uno de los puertos abiertos.

```
# nmap -p135,139,445,3389,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 -sCV 10.129.205.35

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2021-12-13T17:44:50+00:00; +10m23s from scanner time.
| ssl-cert: Subject: commonName=Explosion
| Not valid before: 2021-09-20T16:22:34
|_Not valid after:  2022-03-22T16:22:34
| rdp-ntlm-info:
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2021-12-13T17:44:43+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 10m22s, deviation: 0s, median: 10m22s
| smb2-time:
|   date: 2021-12-13T17:44:44
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

Al igual que en la anterior máquina, que contaba con un sistema operativo Windows, detecto varios puertos abiertos y comienzo intentando enumerar el servicio SMB. Pero, en este caso, no encuentro ningún recurso compartido adicional a los que existen por defecto (reconocidos por tener el carácter "$" al final). Por otra parte, el servicio RPC, que puede usarse para enumerar usuarios y grupos, también se encuentra activo en el puerto 135, pero al intentar acceder sin credenciales, me deniega el acceso.

![Acceso denegado](/assets/img/HTB/Explosion/accessdenied.png)

### Acceso a la máquina

Otro puerto interesante que se encuentra abierto, es el 3389 de [RDP (Remote Desktop Protocol)](https://es.wikipedia.org/wiki/Remote_Desktop_Protocol). RDP es un protocolo propietario de Microsoft que permite conectarnos a un equipo con sistema operativo Windows de forma gráfica, visualizando la interfaz de usuario como si nos encontrasemos en la propia máquina. Por tanto, de manera casi similar a la primera máquina (Meow) pruebo a conectarme utilizando el usuario "Administrator" (usuario administrador por defecto en Windows) utilizando la herramienta `xfreerdp` y sin proporcionar contraseña.

![Conexión por RDP](/assets/img/HTB/Explosion/xfreerdp.png)

Con ello, consigo conectarme a la máquina con permisos de administrador y en el escritorio encuentro el fichero de texto de la flag.

![Flag de la máquina Explosion](/assets/img/HTB/Explosion/flag.png)

### Cuestionario

1. *What does the 3-letter acronym RDP stand for?* (¿Qué significa el acrónimo de 3 letras RDP?)

    Remote Desktop Protocol (Protocolo de Escritorio Remoto)

2. *What is a 3-letter acronym that refers to interaction with the host through a command line interface?* (¿Cuál es el acrónimo de 3 letras que se refiere a la interacción a través de una interfaz de línea de comandos?)

    CLI

3. *What about graphical user interface interactions?* (¿Y a través de una interfaz gráfica de usuario?)

    GUI

4. *What is the name of an old remote access tool that came without encryption by default?* (¿Cuál es el nombre de una vieja herramienta de acceso remoto que viene sin encriptación por defecto?)

    Telnet

5. *What is the concept used to verify the identity of the remote host with SSH connections?* (¿Cuál es el concepto utilizado para verificar la identidad de la máquina remota en conexiones mediante SSH?)

    public-key cryptography (Criptografía de clave pública)

6. *What is the name of the tool that we can use to initiate a desktop projection to our host using the terminal?* (¿Cuál es el nombre de la herramienta que podemos usar para iniciar una sesión de escritorio remoto en nuestra máquina utilizando el terminal?)

    xfreerdp

7. *What is the name of the service running on port 3389 TCP?* (¿Cuál es el nombre del servicio que se está ejecutando en el puerto 3389 de TCP?)

    ms-wbt-server

8. *What is the switch used to specify the target host's IP address when using xfreerdp?* (¿Cuál es el "switch" utilizado para especificar la dirección IP de la máquina objetivo cuando utilizamos xfreerdp?)

    /v:

## MÁQUINA PREIGNITION

### Enumeración de servicios y recopilación de información sensible

Realizo un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- -T5 -vv 10.129.138.225

Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63
```

Una vez obtengo los puertos que la máquina tiene abiertos, utilizo las flags -sC y -sV para aplicar scripts básicos de enumeración e intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p80 -sCV 10.129.138.225

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
```

Solo encuentro el puerto 80 abierto y, al acceder al servidor web a través del navegador, encuentro la página por defecto de Nginx.

![Página por defecto de Nginx](/assets/img/HTB/Preignition/nginx.png)

Por tanto, procedo a realizar una búsqueda de directorios y/o ficheros mediante fuerza bruta utilizando la herramienta `Gobuster`. Como diccionario, utilizo el "common.txt", localizado en la ruta "/usr/share/wordlists/dirb/". Otro diccionario a probar si este no nos aporta demasiados resultados, es el "directory_list_2.3-medium.txt", que se aloja en la ruta "/usr/share/wordlists/dirbuster/". Tras la búsqueda, el único resultado encontrado la ruta "/admin.php".

```
gobuster dir -w /usr/share/wordlists/dirb/common.txt -t 80 -r -u http://10.129.138.225

/admin.php            (Status: 200) [Size: 999]
```

Al acceder a esta ruta, encuentro un panel de login:

![Panel login de la ruta "/admin.php"](/assets/img/HTB/Preignition/login.png)

Para intentar acceder, como no dispongo de credenciales, lo primero que intento es probar usuarios y contraseñas por defecto, consiguiendo así entrar con la combinación admin:admin. Tras acceder, se nos muestra la flag, por lo que el desafío estaría completado.

![Flag de la máquina Preignition](/assets/img/HTB/Preignition/flag.png)

### Cuestionario

1. *What is considered to be one of the most essential skills to possess as a Penetration Tester?* (¿Cuál es considerada una de las habilidades más esenciales para poseer como Pentester?)

    Dir Busting (Búsqueda de directorios mediante fuerza bruta)

2. *What switch do we use for nmap's scan to specify that we want to perform version detection?* (¿Qué "switch" utilizamos en los escaneos de nmap para especificar que queremos realizar una detección de versiones?)

    -sV

3. *What service type is identified as running on port 80/tcp in our nmap scan?* (¿Que tipo de servicio es identificado ejecutándose en el puerto 80 de TCP en nuestro escaneo de nmap?)

    HTTP

4. *What service name and version of service is running on port 80/tcp in our nmap scan?* (¿Qué nombre y versión de servicio está ejecutando en el puerto 80 de TCP en nuestro escaneo de nmap?)

    nginx 1.14.2

5. *What is a popular directory busting tool we can use to explore hidden web directories and resources?* (¿Cuál es una herramienta popular para encontrar directorios y recursos ocultos mediante fuerza bruta que podemos utilizar?)

    gobuster

6. *What switch do we use to specify to gobuster we want to perform dir busting specifically?* (¿Qué "switch" utilizamos para especificar en gobuster que queremos realizar una búsqueda de directorios?)

    dir

7. *What page is found during our dir busting activities?* (¿Qué página es encontrada durante nuestras actividades de búsqueda de directorios?)

    admin.php

8. *What is the status code reported by gobuster upon finding a successful page?* (¿Cuál es el código de estado reportado por gobuster al tener éxito al encontrar una página?)

    200
