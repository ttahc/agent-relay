# Select an installed Python without opening the Microsoft Store alias.
$ErrorActionPreference = 'Stop'
$clientArguments = @($args)
$candidates = [System.Collections.Generic.List[object]]::new()
if ($env:TASKPOOL_PYTHON) {
    $candidates.Add(@($env:TASKPOOL_PYTHON))
} else {
    foreach ($name in @('py', 'python', 'python3')) {
        foreach ($command in @(Get-Command $name -CommandType Application -All -ErrorAction SilentlyContinue)) {
            if ($command.Source -notmatch '[\\/]Microsoft[\\/]WindowsApps[\\/]') {
                $candidateArguments = @($command.Source)
                if ($name -eq 'py') { $candidateArguments += '-3' }
                $candidates.Add($candidateArguments)
            }
        }
    }
    $patterns = @(
        "$env:LOCALAPPDATA\Python\pythoncore-*\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe",
        "$env:USERPROFILE\.local\bin\python*.exe",
        "$env:APPDATA\uv\python\cpython-*-windows-*\python.exe"
    )
    foreach ($pattern in $patterns) {
        foreach ($file in @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
            $candidates.Add(@($file.FullName))
        }
    }
}

foreach ($candidate in $candidates) {
    $pythonExecutable = $candidate[0]
    $prefixArguments = @($candidate | Select-Object -Skip 1)
    try {
        $ready = & $pythonExecutable @prefixArguments -B -I -c 'import sys; print(sys.version_info >= (3, 11))' 2>$null
        if ($LASTEXITCODE -ne 0 -or $ready -ne 'True') { continue }
    } catch {
        continue
    }
    & $pythonExecutable @prefixArguments -B -X utf8 (Join-Path $PSScriptRoot 'round-client.py') @clientArguments
    exit $LASTEXITCODE
}

Write-Error '未找到可运行的 Python 3.11 或更新版本。安装 Python 后重试，或将 TASKPOOL_PYTHON 设置为实际 python.exe 的完整路径。'
exit 1
