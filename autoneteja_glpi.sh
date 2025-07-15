# INICIO SCRIPT

# Ejecutar como administrador

# 1️⃣ Configuración
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Autoneteja"
$secretKey = "1234567890ABCDEF1234567890ABCDEF"  # 32 caracteres exactos

# 2️⃣ Obtener MAC principal
try {
    $macObj = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $macObj) { throw "No se encontró adaptador activo." }
    $mac = $macObj.MacAddress -replace "[:\-]", ""
    Write-Host "✅ MAC detectada: $mac"
} catch {
    Write-Host "❌ Error al obtener MAC: $_"
    pause; exit 1
}

# 3️⃣ Obtener número de serie BIOS
try {
    $serial = (Get-CimInstance Win32_BIOS).SerialNumber
    Write-Host "✅ Serial BIOS detectado: $serial"
} catch {
    Write-Host "❌ Error al obtener número de serie: $_"
    pause; exit 1
}

# 4️⃣ Generar SHA256
try {
    $combined = "$mac$serial"  # si quisiéramos podemos añadir complejidad creando un texto random ($aleatorio = "35Gb%gbVC") y añadirlo a la cadena.
    $sha256Bytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined))
    $sha256Hex = [System.BitConverter]::ToString($sha256Bytes).Replace("-", "").ToLower()
    Write-Host "✅ SHA256: $sha256Hex"
} catch {
    Write-Host "❌ Error al calcular SHA256: $_"
    pause; exit 1
}

# 5️⃣ AES-256 (ECB, PKCS7)
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

# 6️⃣ Registrar en HKLM
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

# Final
Write-Host "🎉 Script finalizado correctamente."
pause

# FINAL SCRIPT
