---
title: Knife (Hack The Box)
author: J0lm3d0
date: 2021-08-28 21:00:00 +0200
categories: [HackTheBox]
tags: [linux, php, cve, sudo, knife_ruby]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Knife de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/Knife/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Knife.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- --open -T5 -n -vv 10.10.10.242

Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```
# nmap -p 22,80 -sC -sV 10.10.10.242

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Al solo encontrarse abiertos los puertos 22 y 80, y no contar con ningún tipo de credenciales, comienzo enumerando el servidor web. En la siguiente imagen se puede ver la página principal que aparece al acceder desde un navegador.

![Página principal del servidor web](img/mainpage.png)

En la página no aparece más información, no existe ningún enlace que nos lleve a otra página ni ningún tipo de pista en el código fuente. Por tanto, procedo a realizar una búsqueda mediante fuerza bruta de directorios y/o ficheros ocultos con el script `http-enum` de *Nmap* y con `Gobuster`. La búsqueda mediante *http_enum* nos encuentra el directorio "icons", mientras que en la búsqueda con *Gobuster*, utilizando el diccionario "directory-list-2.3-medium'' de `Dirbuster`, se observa que solo encuentra el típico "server-status".

```
# nmap --script http-enum -p80 10.10.10.242

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /icons/: Potentially interesting folder
```

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.242

/server-status        (Status: 403) [Size: 277]

```

Al acceder al directorio "icons", observo que es similar a la página principal tanto en la apariencia como en el código fuente. Por tanto, vuelvo a realizar fuzzing con *Gobuster* y encuentro otro directorio: "small''.

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.242/icons

/small                (Status: 301) [Size: 318] [--> http://10.10.10.242/icons/small/]

```

Pero, al acceder ahora a la ruta "icons/small", me encuentro con el mismo problema que anteriormente, la página es similar a la principal y no se observa ninguna diferencia en el código fuente ni en la apariencia. Repito el procedimiento y vuelvo a realizar fuzzing, pero ya no obtengo ningún resultado.

En este punto, se me ocurre mirar con que tecnologías está trabajando el servidor por detrás y, por supuesto, las versiones de estas. Por tanto, utilizo la herramienta `WhatWeb` especificando las 3 páginas que he encontrado. También se podría utilizar el plugin `Wappalyzer`, disponible en la mayoría de navegadores.

![Enumeramos las tecnologías que utiliza el servidor web](img/whatweb.png)

Del resultado obtenido consigo enumerar que el servidor web está utilizando PHP 8.1.0-dev, ya que la versión de Apache la obtuve mediante *Nmap* previamente. Busco esta versión con la herramienta `SearchSploit` y veo que existe un exploit que permite ejecución remota de código.

![Búsqueda de exploits para la versión de PHP](img/searchsploit.png)

## Acceso a la máquina

La explotación consiste en incluir una cabecera "User-Agentt" en la petición al servidor web, que contendrá la llamada a una función "zerodiumsystem", cuyo argumento será el comando que queramos ejecutar a nivel de sistema. Tras buscar información en Internet, compruebo que está vulnerabilidad se trata de una puerta trasera (backdoor) en el código fuente que colocaron unos ciberdelincuentes después de conseguir acceder al repositorio GIT interno de PHP.

![Script en Python que explota la vulnerabilidad de la versión de PHP](img/phpexploit.png)

Al lanzar el script me pide introducir la URL completa y, como es correcta y el servidor es vulnerable, comienza a simularme una shell, aunque, como se ha visto, por detrás está realizando una petición HTTP cada vez que escribo un comando. Intento lanzarme una shell inversa utilizando este exploit, pero no llega a realizarse correctamente. Por tanto, recurro a la herramienta `Curl` para realizar una petición que me envíe una shell de la máquina víctima a mi máquina.

![Utilizamos curl para lanzarnos una shell inversa](img/revshell.png)

Veo que obtengo la shell como el usuario "james", por lo que pruebo a sacar la flag de usuario no privilegiado y se me permite visualizarla correctamente.

```
james@knife:~$ cat user.txt

84cd1f49476013bb338bc651c29ab191
```

## Escalada de privilegios

Una vez dentro de la máquina, comienzo a enumerar el sistema para intentar escalar privilegios. Primero enumero los binarios con bit SUID activado que se encuentran en el sistema, pero este caso no encuentro ningún binario que pudiese aprovechar ni ningún binario personalizado o creado por el usuario.

Con el comando *sudo -l* compruebo si puede ejecutarse algún archivo con privilegios de otro usuario o sin proporcionar contraseña. En este caso, se puede ejecutar *knife* con privilegios de "root" y sin proporcionar contraseña. También hago uso del comando *file* para saber el tipo de archivo que es, y compruebo que se trata de un archivo ejecutable programado en Ruby.

![Enumeramos el tipo de archivo que es *knife*](img/knifefile.png)

Tras buscar información sobre este archivo de Ruby en internet, compruebo que existe una manera de ejecutar código Ruby, utilizando el subcomando *exec*. Con este subcomando puede lanzarse código escrito en la misma línea o pasar como argumento un script previamente creado.

![Documentación sobre *knife*](knifedoc.png)

En este caso, al poder ejecutar *knife* con permisos de "root", ejecuto el código en Ruby correspondiente al lanzamiento de una shell, para así obtener una shell como usuario privilegiado y tener acceso total a la máquina, pudiendo visualizar la flag final.

```
james@knife:~$ sudo knife exec -E "exec '/bin/bash -i'"

bash: cannot set terminal process group (1028): Inappropiate ioctl for device
bash: no job control in this shell

root@knife:/home/james# cat /root/root.txt

cf5429e70e95ad1c663402740fe00aa22
```
