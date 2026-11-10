param(
    [Parameter(Mandatory)]
    [ValidateSet('Enable', 'Disable')]
    [string] $Action,
    [Parameter(Mandatory)]
    [int] $InterfaceIndex,
    [string] $ReportPath
)

$ErrorActionPreference = 'Stop'
$ruleName = 'T22-TaskPool-Phase1-LAN'
$port = 18443
$backendPort = 18765
$mappingName = "0.0.0.0/$port"
$target = "127.0.0.1/$backendPort"
$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
$netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'

function Get-T22Mapping {
    if (Test-Path -LiteralPath $registryPath) {
        $settings = Get-ItemProperty -LiteralPath $registryPath
        $property = $settings.PSObject.Properties[$mappingName]
        if ($property) { return $property.Value }
    }
}

function Invoke-T22Netsh {
    param([string[]] $Arguments)
    $result = & $netsh interface portproxy @Arguments
    if ($LASTEXITCODE -ne 0) { throw ($result -join [Environment]::NewLine) }
}

try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '需要在管理员 PowerShell 中运行，以添加本机端口转发和限定网卡的入站规则。'
    }
    $mapping = Get-T22Mapping
    $rule = Get-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue
    if (($mapping -and $mapping -ne $target) -or ($mapping -and !$rule)) {
        throw "端口 $port 已有其他映射，已保留现状。"
    }
    if ($Action -eq 'Disable') {
        if ($mapping) {
            Invoke-T22Netsh @('delete', 'v4tov4', "listenport=$port", 'listenaddress=0.0.0.0')
            if (Get-T22Mapping) { throw '端口映射仍存在。' }
        }
        if ($rule) { $rule | Remove-NetFirewallRule }
        $result = @{ status = 'disabled'; port = $port }
    } else {
        $nic = @(Get-NetAdapter -Physical | Where-Object ifIndex -eq $InterfaceIndex)
        if ($nic.Count -ne 1 -or $nic[0].Status -ne 'Up') {
            throw '未找到指定且处于连接状态的物理网卡。'
        }
        $interface = $nic[0].Name
        if (!$mapping -and (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)) {
            throw "端口 $port 已有监听进程，已保留现状。"
        }
        $createdRule = $false
        if ($rule) {
            $existing = $rule | Get-NetFirewallInterfaceFilter
            if (@($existing.InterfaceAlias).Count -ne 1 -or $existing.InterfaceAlias -ne $interface) {
                throw '已有 T22 规则绑定到其他网卡，请先核对现有规则。'
            }
        } else {
            $rule = New-NetFirewallRule -Name $ruleName -DisplayName 'T22 本机 Podman HTTPS' `
                -PolicyStore PersistentStore -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port `
                -RemoteAddress LocalSubnet -InterfaceAlias $interface -Profile Any -EdgeTraversalPolicy Block
            $createdRule = $true
        }
        if (!$mapping) {
            try {
                Invoke-T22Netsh @('add', 'v4tov4', "listenport=$port", 'listenaddress=0.0.0.0',
                                  "connectport=$backendPort", 'connectaddress=127.0.0.1')
                if ((Get-T22Mapping) -ne $target) { throw '转发规则未生效。' }
            } catch {
                if ($createdRule -and !(Get-T22Mapping)) { $rule | Remove-NetFirewallRule }
                throw
            }
        }
        $addresses = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 |
            Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -ExpandProperty IPAddress)
        $result = @{ status = 'enabled'; interface = $interface; interface_index = $InterfaceIndex
                     ip_addresses = $addresses; port = $port; backend = $target }
    }
    $json = $result | ConvertTo-Json -Compress
    if ($ReportPath) { Set-Content -LiteralPath $ReportPath -Value $json -Encoding utf8 }
    $json
} catch {
    if ($ReportPath) {
        @{ status = 'error'; message = $_.Exception.Message } | ConvertTo-Json -Compress |
            Set-Content -LiteralPath $ReportPath -Encoding utf8
    }
    throw
}
