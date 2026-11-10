param(
    [Parameter(Mandatory)]
    [ValidateSet('Enable', 'Check', 'Disable')]
    [string] $Action,
    [guid] $InterfaceGuid,
    [string] $Address,
    [string] $Subnet
)

$ErrorActionPreference = 'Stop'
$name = 'IntranetTaskPool-EasyTier'
$port = 18443
$marker = 'Intranet task service EasyTier ingress managed by Set-EasyTierIngress.ps1'
$store = 'PersistentStore'
$rule = Get-NetFirewallRule -Name $name -PolicyStore $store -ErrorAction SilentlyContinue

if ($rule -and $rule.Description -ne $marker) {
    throw 'A rule with this name has different ownership. Check it manually.'
}
if ($Action -in @('Enable', 'Disable')) {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run Enable or Disable in administrator PowerShell.'
    }
}
if ($Action -eq 'Disable') {
    if ($rule) { $rule | Remove-NetFirewallRule }
    [ordered]@{ status = 'disabled'; rule = $name } | ConvertTo-Json -Compress
    return
}

if (!$InterfaceGuid -or !$Address -or !$Subnet) {
    throw 'Specify -InterfaceGuid, -Address and -Subnet for the EasyTier adapter.'
}
$nic = @(Get-NetAdapter -IncludeHidden | Where-Object { [guid]$_.InterfaceGuid -eq $InterfaceGuid })
if ($nic.Count -ne 1 -or $nic[0].Status -ne 'Up' -or $nic[0].Name -notlike 'et_*') {
    throw 'The selected EasyTier adapter is missing or down.'
}
if ($Subnet -notmatch '^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$') {
    throw 'Specify a single EasyTier IPv4 CIDR.'
}
$prefix = [int]$Matches[2]
if ($prefix -lt 16 -or $prefix -gt 32) { throw 'The EasyTier prefix must be between /16 and /32.' }
$ip = @(Get-NetIPAddress -InterfaceIndex $nic[0].ifIndex -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -eq $Address -and $_.AddressState -eq 'Preferred' -and $_.PrefixLength -eq $prefix
})
if ($ip.Count -ne 1) { throw 'The selected address and prefix are not active on the EasyTier adapter.' }
$route = @(Get-NetRoute -InterfaceIndex $nic[0].ifIndex -AddressFamily IPv4 | Where-Object {
    $_.DestinationPrefix -eq $Subnet -and $_.NextHop -eq '0.0.0.0'
})
if (!$route) { throw 'The specified subnet is not a directly connected EasyTier route.' }
$mapping = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp')."0.0.0.0/$port"
if ($mapping -ne '127.0.0.1/18765') { throw 'The existing task service port proxy does not match the expected local endpoint.' }

if (!$rule -and $Action -eq 'Enable') {
    $rule = New-NetFirewallRule -Name $name -DisplayName 'Intranet Task Service EasyTier HTTPS' -Description $marker `
        -PolicyStore $store -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort $port `
        -LocalAddress $Address -RemoteAddress $Subnet -InterfaceAlias $nic[0].Name -Profile Any -EdgeTraversalPolicy Block
}
if (!$rule) { throw 'The EasyTier rule is not installed.' }
$effective = Get-NetFirewallRule -Name $name -PolicyStore ActiveStore
$ports = $effective | Get-NetFirewallPortFilter
$addresses = $effective | Get-NetFirewallAddressFilter
$interfaces = $effective | Get-NetFirewallInterfaceFilter
$mask = (0..3 | ForEach-Object {
    $bits = [Math]::Max(0, [Math]::Min(8, $prefix - 8 * $_))
    [int](256 - [Math]::Pow(2, 8 - $bits))
}) -join '.'
$network = $Subnet.Split('/')[0]
if ($effective.Enabled -ne 'True' -or $effective.Action -ne 'Allow' -or $effective.Direction -ne 'Inbound' -or
    $ports.Protocol -notin @('TCP','6') -or @($ports.LocalPort).Count -ne 1 -or $ports.LocalPort -ne "$port" -or
    @($addresses.LocalAddress).Count -ne 1 -or $addresses.LocalAddress -notin @($Address,"$Address/32","$Address/255.255.255.255") -or
    @($addresses.RemoteAddress).Count -ne 1 -or $addresses.RemoteAddress -notin @($Subnet,"$network/$mask") -or
    @($interfaces.InterfaceAlias).Count -ne 1 -or $interfaces.InterfaceAlias -ne $nic[0].Name) {
    throw 'The active rule differs from the requested adapter, address, subnet or port. Disable and recreate it after review.'
}
[ordered]@{ status = 'enabled'; rule = $name; interface = $nic[0].Name; address = $Address
            subnet = $Subnet; port = $port; backend = $mapping } | ConvertTo-Json -Compress
