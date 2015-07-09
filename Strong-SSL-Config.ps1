# Created by: Tyler McCamant (tmccamant@gmail.com)

# Re-create the protocols key.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Force | Out-Null
 
# Disable weak protocols
$weakProtocols = @(
	'Multi-Protocol Unified Hello',
	'PCT 1.0',
	'SSL 2.0',
	'SSL 3.0'
)
Foreach ($protocol in $weakProtocols) {
New-Item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server -Force | Out-Null
New-Item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server -name DisabledByDefault -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client -name DisabledByDefault -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
}

# Enable strong protocols
$strongProtocols = @(
	'TLS 1.0',
	'TLS 1.1',
	'TLS 1.2'
)
Foreach ($protocol in $strongProtocols) {
New-Item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server -Force | Out-Null
New-Item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
}

# Re-create the ciphers key.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null

# Disable Weak Ciphers
$weakCiphers = @(
	'DES 56/56',
	'NULL',
	'RC2 128/128',
	'RC2 40/128',
	'RC2 56/128',
	'RC4 40/128',
	'RC4 56/128',
	'RC4 64/128',
	'RC4 128/128'
)
Foreach ($cipher in $weakCiphers) {
$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true).CreateSubKey($cipher)
$key.SetValue('Enabled', 0, 'DWord')
$key.Close()
}

# Enable Strong Ciphers
$strongCiphers = @(
	'AES 128/128',
	'AES 256/256',
	'Triple DES 168/168'
)
Foreach ($cipher in $strongCiphers) {
$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers", $true).CreateSubKey($cipher)
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
$key.Close()
}

# Recreate the hashes key
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null

# Enable Hashes
$strongHashes = @(
	'MD5',
	'SHA',
	'SHA 256',
	'SHA 384',
	'SHA 512'
)
Foreach ($hash in $strongHashes) {
$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes", $true).CreateSubKey($hash)
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
$key.Close()
}

# Recreate the KeyExchangeAlgorithms key
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null

# Enable KeyExchangeAlgorithms
$strongKeyExchanges = @(
	'Diffie-Hellman',
	'ECDH',
	'PKCS'
)
Foreach ($keyExchange in $strongKeyExchanges) {
$key = (get-item HKLM:\).OpenSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms", $true).CreateSubKey($keyExchange)
New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$keyExchange" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
$key.Close()
}

# Set cipher order
$cipherOrder = @(
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256',
  'TLS_RSA_WITH_AES_256_GCM_SHA384',
  'TLS_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_RSA_WITH_AES_256_CBC_SHA256',
  'TLS_RSA_WITH_AES_256_CBC_SHA',
  'TLS_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_RSA_WITH_AES_128_CBC_SHA',
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
)

$cipherOrderString = [string]::join(',', $cipherOrder)
New-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -name 'Functions' -value $cipherOrderString -PropertyType 'String' -Force | Out-Null
