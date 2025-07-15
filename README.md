# SECURIZACIÓN DEL CANAL UPSTREAM EN AGENTE-GLPI

Este documento explica por qué el uso de GLPI Agent sin medidas adicionales de seguridad puede abrir la puerta a vulnerabilidades críticas, proponiendo mecanismos avanzados para garantizar la autenticación y securización del canal de envío de inventarios

El agente glpi es un ejecutable que se instala en las máquinas que forman parte de una red a inventariar. De forma regular envía los datos del software y hardware del elemento informático donde reside hacia un servidor que los almacena. Esto permite a las organizaciones disponer de un inventario completo, exacto e instantáneo del parque informático disponible, así como asociarlo a usuarios o tickets de servicio.

Como todo agente que se instala en un dispositivo y tiene acceso completo al mismo, la seguridad en la instalación y el desempeño es un factor determinante. La instalación del agente permite seleccionar diversas opciones que securizan el canal de conexión. En primer lugar el servidor que recoge los datos debe estar obligatoriamente protegido con un certificado SSL/TLS. Por esta razón la url de la instalación debe ser del tipo "https://__url__del__servidor"

Una de las opciones, accesible si descargamos el ejecutable y optamos por la instalación customizada o completa, consiste en añadir el pem y el fingerprint del servidor. 

Si entramos en la url del servidor usando Firefox, luego pulsamos sobre el icono del candado y verificamos el certificado, podremos descargar el PEM de la cadena y el fingerprint (el hash SHA256), añadirlos por separado a un documento de texto y cargarlos en el apartado indicado. Por ejemplo, los guardamos en C:\certs\fingerprint.txt y C:\certs\mi_servidor.pem y con estas urls los introducimos en el instalador. Esto es útil para certificados autofirmados pero no es necesario si disponemos de un certificado emitido por una entidad de confianza (Sectigo, DigiCert etc). En este último caso el certificado raíz ya suele estar en el contenedor de certificados del sistema y la conexión no se debe re-autenticar. Por tanto esta opción aunque no securiza la conexión de forma adicional, permite al menos complicar los ataques MITM ya que obligaría al hacker a reproducir también la firma y el .pem del servidor fake que acondicionara. Conviene aclarar que el fingerprint no añade seguridad en certificados de CA pública porque el sistema operativo ya valida la cadena hasta la CA raíz. Solo en casos de autofirmados o CA privada cobra importancia.

Otra opción de securización consiste en emplear un proxy que de forma intermedia conecte el agente con el servidor que recoge los inventarios. 

Si el proxy está dentro de nuestra red y no es accesible externamente puede ser una opción para securizar el canal del agente. Casi con seguridad el proxy existía previamente y era la manera en que los usuarios de la red podían acceder a Internet. El proxy contaría con una conexión al router y éste, por NAT, accedería al exterior con una ip pública. Aunque esta conexión puede parecer segura para el agente glpi, lo sería si y sólo si el servidor aceptara la conexión solo desde la ip pública y por medio de un túnel VPN SSL (encriptado). No obstante cabe aclarar que realizar un handshake entre un router y un servidor Apache o Nginx no es tan sencillo ni inmediato como el proceso similar que ocurre entre los navegadores y las páginas web con certificado SSL. Tampoco una securización por ip exclusiva supone asegurar el canal que aún queda expuesto a ataques MITM si, como hemos dicho, no encriptamos los datos que viajan por el mismo.

Si empleamos un proxy externo con ip pública, aunque sea de nuestra propiedad, el asunto se complica. El agente glpi guarda la configuración en text claro en el registro de Windows, por lo que un malware podría extraer los datos y no solo acceder a nuestro sistema, sino incluso comprometer el proxy y con ello a toda nuestra red. Por ello no es conveniente introducir datos comprometedores en la configuración del agente si los guarda en texto claro (que es tal y como sucede).

En un entorno ideal el agente-glpi debería poder realizar handshake con el servidor de inventarios de manera que el canal quedara completamente securizado (es decir, que funcionara igual que cualquier navegador Chrome, Firefox, Opera etc). Además la autenticación añadiría una capa extra de privacidad a la conexión. Tal cosa a día de hoy no ocurre, tal y como explica Teclib al respecto:

https://help.glpi-project.org/tutorials/inventory/secure_agent#references

Existen varias maneras externas de asegurar el canal entre el agente y el servidor de inventario. Todas tienen sus pros y sus contras.

- VPN SSL : 

Este escenario supone que el ordenador del usuario abre una VPN contra el proxy, encriptando los datos ascendentes. El inconveniente es que dicho túnel debería estar abierto durante el funcionamiento de la máquina mientras que el uso del mismo sería en realidad de unos pocos minutos cada 24 horas (muchos recursos dispuestos para poco tiempo de actuación), aparte de que la gestión de un número importante de conexiones VPN puede resultar compleja.

- SSO/Tailscale:

En este escenario las máquinas están dadas de alta en un sistema SSO o en una red privada construida sobre el mismo principio, como por ejemplo Tailscale/Headscale o Wireguard. En este caso el usuario se da de alta en la red "lógica" y el agente envía los datos sin tener que hacer nada en especial salvo mantener el equipo conectado. Este proceso requiere que el sistema agente-servidor se integre en la red lógica y que forme parte de la red de la organización. Si bien es una buena solución, tipo zero trust, lamentablemente su relativa novedad - hablamos del año 2020 - es un problema para equipos técnicos poco dados a la innovación.

Si ninguna de de las opciones anteriores es viable, debemos optar por una securización ad-hoc. Antes de explicarla conviene aclarar por qué es tan importante:

GLPI funciona por un sistema de PUSH: el agente, de forma autónoma, envía los datos que recolecta cada cierto tiempo. En el momento estipulado por el cron interno lo primero que hace es establecer un aviso :

<?xml version="1.0" encoding="UTF-8"?>
<REQUEST>
  <DEVICEID>DESKTOP-xxxx-2025-03-02-07-46-05</DEVICEID>
  <QUERY>PROLOG</QUERY>
  <TOKEN>12345678</TOKEN>
</REQUEST>

Básicamente indica "soy la máquina DESKTOP-xxxx y en el día y hora 2025-03-02-07-46-05 establezco una comunicación para enviar los datos de mi inventario". El nombre del dispositivo se etiqueta como <DEVICEID>....</DEVICEID> y la demanda PROLOG entre etiquetas <QUERY>....</QUERY>. ¿Y el token? Pues como ya os habéis dado cuenta, emplea un token 12345678 lo cual o bien es un descuido o bien no sirve de nada. En realidad es lo segundo. Cómo no hay handshake ni diálogo, todo es push, el TOKEN no realiza ninguna función aparte de mostrar que ese sería el camino pero en realidad no es nada.

Tras esta declaración inicial el agente envía el PAYLOAD con un formato .ocs, .xml o json (dependiendo de la versión) con el contenido de hardware y software del equipo.

<?xml version="1.0" encoding="UTF-8" ?>

<CONTENT>

  [...aquí iría el inventario de software y hardware...]

</CONTENT>  
// y finalizaría con la solicitud de inventario <QUERY>INVENTORY</QUERY>, es decir, "estoy haciendo el inventario" y de nuevo DEVICEID+Timestamp

  <DEVICEID>DESKTOP-xxxx-2025-03-02-07-58-05</DEVICEID>
  <QUERY>INVENTORY</QUERY>
</REQUEST>

Si no existe tramitación de token, password o certificado, ni control por IP o similar, bastaría con declarar una máquina cualquiera para que los datos de la misma subieran al servidor, aunque la misma no formara parte de nuestra organización. Tal cosa podría derivar en un posible ataque DDoS (saturación del servidor al intentar dar de alta miles de máquinas) o incluso una inyección SQL si la base de datos no estuviera protegida.

Respecto al ataque DDoS no es ni siquiera necesario tener máquinas. Basta con crear un script, abrir PROLOG y enviar el PAYLOAD por curl o similar. De esta manera una organización podría ver como en lugar de 300 máquinas dispone de 1000 en cuestión de segundos, causando probablemente malfunción en la base de datos y/o el servidor.

Por otro lado la inyección SQL se podría dar ocultando comandos perjudiciales entre los tags XML, por ejemplo:

<DEVICEID>INSERT INTO glpi_computers (deviceid) VALUES ('PC-TEST'); DROP TABLE glpi_computers;--');</DEVICEID>

El anterior tag podría provocar el borrado de la tabla glpi_computers. Esto no significa que GLPI no se proteja de este tipo de ataques, pero siempre deberemos mantenernos en alerta ya que un bug de MariaDB/MySQL o un error en el PHP podrían desencadenar un proceso de hackeo fatal.

En resumen: no solo hemos de securizar la conexión entre agente y servidor, si no también autenticar la conexión. 

Lo primero sirve para ocultar el inventario de la máquina - con las posibles debilidades que serían visibles en caso contrario - y lo segundo para que solo las máquinas autorizadas puedan conectarse al servidor. 

Dado que la arquitectura actual de GLPI Agent carece de mecanismos sólidos de autenticación y handshake, es responsabilidad de cada organización implementar medidas compensatorias que mitiguen el riesgo, incluyendo proxys autenticados, VPNs dedicadas o sistemas de validación ad-hoc, al menos hasta que el fabricante provea una solución oficial.

AUTENTICACIÓN Y SECURIZACIÓN A TRAVÉS DE PROXY EXTERNO

Tenemos una red a inventariar que hasta la fecha se conectaba directamente con el servidor que recoge los informes de cada agente glpi. Este método, por las razones expuestas, es inseguro y puede provocar daños tanto en las máquinas a inventariar como en el servidor.

Para securizar y autenticar necesitamos desacoplar el servidor que recopilaba inventarios e interponer un proxy entre éste y los agentes. El proxy contará con un certificado TLS sobre un dominio tipo https://mi_proxy.com de manera que los agentes glpi reportaran ahora contra dicha url.

Para autenticar + verificar que realmente el ordenador corresponde a nuestra red existen varios niveles de complejidad, desde el "simple" que solo verifica por ejemplo que la máquina cuenta con un determinado programa instalado hasta el que descodifica ciertos valores "ocultos" del ordenador y los compara con una tabla previamente insertada en el servidor: si hay coincidencia, el inventario progresa, en caso contrario, queda retenido.

Una solución consistiría en instalar un programa fake en el ordenador de manera que quede inventariado y, lo más importante, quede reflejado en el registro del sistema. De hecho GLPI realiza el inventario sobre los registros de Windows, por lo que un programa que no los cree nunca se verá reflejado.

Vamos a crear un programa que se llamará Autoneteja. Lo único que hace es crear un hash 256 de la unión de la MAC detectada y el número de serie del dispositivo. Podría ser otro tipo de dato, hemos elegido un par que en principio se mantienen constantes aunque de todos es sabido que ambos pueden modificarse por fuerza bruta. Una vez calculado el hash, se codifica en AES256 con $SecretKey= "1234567890ABCDEF1234567890ABCDEF". El nombre del programa ("autoneteja") y la llave secreta se puede modificar según nuestra conveniencia. 

Para el primer sistema de autenticación, el más simple, no vamos a necesitar la encriptación simétrica, pero nos será útil para los sistemas avanzados que veremos más adelante. En el registro windows se crearán estas cuatro entradas, con lo que nos aseguramos que GLPI los leerá.

"DisplayName" : "autoneteja" 
"DisplayVersion" : $encryptedBase64
"Publisher" : "TierraMedia"
"InstallDate" : (Get-Date -Format "yyyyMMdd")

El script de abajo lo copiamos en PowerShell con permisos de administrador, ejecutándolo a continuación.

//INICIO SCRIPT

// Ejecutar como administrador

// 1️⃣ Configuración
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Autoneteja"
$secretKey = "1234567890ABCDEF1234567890ABCDEF"  # 32 caracteres exactos

// 2️⃣ Obtener MAC principal
try {
    $macObj = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $macObj) { throw "No se encontró adaptador activo." }
    $mac = $macObj.MacAddress -replace "[:\-]", ""
    Write-Host "✅ MAC detectada: $mac"
} catch {
    Write-Host "❌ Error al obtener MAC: $_"
    pause; exit 1
}

// 3️⃣ Obtener número de serie BIOS
try {
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber
    Write-Host "✅ Serial BIOS detectado: $serial"
} catch {
    Write-Host "❌ Error al obtener número de serie: $_"
    pause; exit 1
}

// 4️⃣ Generar SHA256
try {
    $combined = "$mac$serial"  # si quisiéramos podemos añadir complejidad creando un texto random ($aleatorio = "35Gb%gbVC") y añadirlo a la cadena.
    $sha256Bytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined))
    $sha256Hex = [System.BitConverter]::ToString($sha256Bytes).Replace("-", "").ToLower()
    Write-Host "✅ SHA256: $sha256Hex"
} catch {
    Write-Host "❌ Error al calcular SHA256: $_"
    pause; exit 1
}

// 5️⃣ AES-256 (ECB, PKCS7)
try {
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($secretKey)
    if ($keyBytes.Length -ne 32) { throw "Clave secreta no tiene 32 bytes." }

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keyBytes
    $aes.Mode = "ECB"
    $aes.Padding = "PKCS7"

    $encryptor = $aes.CreateEncryptor()
    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($sha256Hex)
    $encryptedBytes = $encryptor.TransformFinalBlock($hashBytes, 0, $hashBytes.Length)
    $encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)
    Write-Host "✅ Encriptado AES (Base64): $encryptedBase64"
} catch {
    Write-Host "❌ Error al encriptar: $_"
    pause; exit 1
}

// 6️⃣ Registrar en HKLM
try {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "✅ Clave de registro creada."
    }

    Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "autoneteja" -Force
    Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value $encryptedBase64 -Force
    Set-ItemProperty -Path $regPath -Name "Publisher" -Value "TierraMedia" -Force
    Set-ItemProperty -Path $regPath -Name "InstallDate" -Value (Get-Date -Format "yyyyMMdd") -Force

    Write-Host "✅ Registro completado en: $regPath"
} catch {
    Write-Host "❌ Error al escribir en el registro: $_"
    pause; exit 1
}

// Final
Write-Host "🎉 Script finalizado correctamente."
pause

// FINAL SCRIPT

Tras la instalación, si no se han dado errores, revisaremos el registro con Regedit para asegurarnos que los cuatro procesos aparecen. Seguidamente procedemos a forzar un inventario entrando en el ordenador a través de Navegador (Chrome, Firefox, Edge etc) : http://localhost:62354 (luego hablaremos de esto, otro punto peligroso en la seguridad de GLPI ya que este puerto abierto en localhost permite explorar la API local del agente, lo que puede exponer datos de inventario o configuración si el endpoint no está bien restringido o si malware local lo consulta.).

Al cabo de un rato el ordenador estará inventariado y mostrará, entre otros, software "Autoneteja". Esta es la muestra real del inventario. Como se ve "autoneteja" está entre la AutoFirma y el Configurador FNMT, por lo que a ojos del sistema, es un software legítimo.

<SOFTWARES>
      <ARCH>x86_64</ARCH>
      <FROM>registry</FROM>
      <GUID>AutoFirma</GUID>
      <INSTALLDATE>09/05/2025</INSTALLDATE>
      <NAME>AutoFirma</NAME>
      <PUBLISHER>Gobierno de España</PUBLISHER>
      <SYSTEM_CATEGORY>application</SYSTEM_CATEGORY>
      <UNINSTALL_STRING>C:\Program Files\AutoFirma\uninstall.exe</UNINSTALL_STRING>
      <VERSION>1.8.3</VERSION>
    </SOFTWARES>
    <SOFTWARES>
      <ARCH>x86_64</ARCH>
      <FROM>registry</FROM>
      <GUID>Autoneteja</GUID>
      <INSTALLDATE>14/05/2025</INSTALLDATE>
      <NAME>autoneteja</NAME>
      <PUBLISHER>TierraMedia</PUBLISHER>
      <SYSTEM_CATEGORY>application</SYSTEM_CATEGORY>
      <VERSION>7YBK68rDHgi+nusuYrjPwxoYnIl8LPsL6Ghl3PVPpNPp/Ez3an7zQckfAK3MnHaIvb7zGLexhF6bYPlgrfnYtCACFUryrIEJuP59zg426OI=</VERSION>
    </SOFTWARES>
    <SOFTWARES>
      <ARCH>x86_64</ARCH>
      <FROM>registry</FROM>
      <GUID>ConfiguradorFnmt</GUID>
      <INSTALLDATE>04/06/2025</INSTALLDATE>
      <NAME>Configurador FNMT</NAME>
      <PUBLISHER>FNMT-RCM</PUBLISHER>
      <SYSTEM_CATEGORY>application</SYSTEM_CATEGORY>
      <UNINSTALL_STRING>C:\Program Files\ConfiguradorFnmt\uninstall.exe</UNINSTALL_STRING>
      <VERSION>5.0.0</VERSION>
    </SOFTWARES>

En el script teníamos este codificación:

 $encryptor = $aes.CreateEncryptor()
    $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($sha256Hex)
    $encryptedBytes = $encryptor.TransformFinalBlock($hashBytes, 0, $hashBytes.Length)
    $encryptedBase64 = [Convert]::ToBase64String($encryptedBytes)

Es decir, que convertimos la cadena SHA256 en un código simétrico AES y este, a su vez, lo convertimos en un Base64 ($encryptedBase64)

Este código en Base64 lo introducimos en el Registro de esta manera:

Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value $encryptedBase64 -Force

Por tanto, en este bloque:

<GUID>Autoneteja</GUID>
      <INSTALLDATE>14/05/2025</INSTALLDATE>
      <NAME>autoneteja</NAME>
      <PUBLISHER>TierraMedia</PUBLISHER>
      <SYSTEM_CATEGORY>application</SYSTEM_CATEGORY>
      <VERSION>7YBK68rDHgi+nusuYrjPwxoYnIl8LPsL6Ghl3PVPpNPp/Ez3an7zQckfAK3MnHaIvb7zGLexhF6bYPlgrfnYtCACFUryrIEJuP59zg426OI=</VERSION>

La <VERSION> en realidad representa Base64 de AES256 sobre SHA256 de la MAC y el número de serie. Al descodificarlo en el proxy (ya que tenemos la clave secreta del AES) deberíamos obtener la MAC, el número de serie y el texto aleatorio (si lo hubiéramos incluido). Esto supone que si la información se encuentra en la base de datos del proxy, la información progresa. 

Pero, ¿qué ocurre si por MITM se intercepta el payload del inventario y se reenvía, añadiendo código malicioso? 

Esto lo veremos en un paso más avanzado y propondremos una solución más compleja. Conviene aclara también que:

Un proxy no es un mecanismo oficial soportado por GLPI.

Tampoco previene ataques MITM entre agente y proxy.

No impide que se reinyecten paquetes previamente capturados si no usas rotación de clave o tokens únicos.

SÍ es eficaz como capa de filtrado, pero no sustituye un mecanismo robusto como mutual TLS (de lo que ya sabemos que carece GLPI).

En cualquier caso, vamos a poner las cosas difíciles a los hackers.
