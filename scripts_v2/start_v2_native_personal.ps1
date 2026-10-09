# Personal DC v2 native Windows MCP (NO Docker) behind the existing v2 tunnel.
# Launch only after the v2 showcase listener 18766 has been stopped.
# Never touches the active v1 18765 process or tunnel configuration.
[CmdletBinding()]
param()
$ErrorActionPreference="Stop"
Add-Type -AssemblyName System.Security
$Root=Split-Path -Parent $PSScriptRoot
$Secret=Join-Path $env:LOCALAPPDATA "Personal_DC_V2\secrets\backend-key.dpapi"
if(-not(Test-Path $Secret)){throw "V2_BACKEND_SECRET_NOT_FOUND"}
$existing=Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 18766 -State Listen -ErrorAction SilentlyContinue
if($existing){throw "V2_PORT_IN_USE_STOP_SHOWCASE_ONLY_FIRST"}
$encrypted=[IO.File]::ReadAllBytes($Secret)
$clear=$null
try{
    $clear=[Security.Cryptography.ProtectedData]::Unprotect(
       $encrypted,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $key=[Text.Encoding]::UTF8.GetString($clear)
    if($key -cnotmatch "^[0-9a-f]{64}$"){throw "V2_BACKEND_SECRET_INVALID"}
    $env:PDC_V2_BACKEND_KEY=$key
    $env:CONTROL_PLANE_API_KEY=$null
    $env:OPENAI_ADMIN_KEY=$null
    $env:PERSONAL_DC_HOME=$Root
    $Python="C:\Python314\python.exe"
    $logdir=Join-Path $env:LOCALAPPDATA "Personal_DC_V2\logs"
    $stamp=(Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfff")
    $logOut=Join-Path $logdir ("native-"+$stamp+".stdout.log")
    $logErr=Join-Path $logdir ("native-"+$stamp+".stderr.log")
    $proc=Start-Process -FilePath $Python -ArgumentList "-m","dc_v2.native_personal_mcp" -WorkingDirectory $Root -PassThru -WindowStyle Hidden -RedirectStandardOutput $logOut -RedirectStandardError $logErr
    $deadline=(Get-Date).AddSeconds(20)
    do{
      Start-Sleep -Milliseconds 250
      $up=Get-NetTCPConnection -LocalAddress "127.0.0.1" -LocalPort 18766 -State Listen -ErrorAction SilentlyContinue
    }while(-not $up -and -not $proc.HasExited -and (Get-Date) -lt $deadline)
    if(-not $up){throw "NATIVE_V2_BACKEND_NOT_LISTENING"}
    $PidFile=Join-Path $env:LOCALAPPDATA "Personal_DC_V2\run\backend.pid"
    [IO.File]::WriteAllText($PidFile,[string]$proc.Id)
    Write-Output ("V2_NATIVE_WINDOWS_MCP_READY_PID="+$proc.Id)
    Write-Output "V2_NATIVE_NO_DOCKER"
}finally{
    $env:PDC_V2_BACKEND_KEY=$null
    $env:CONTROL_PLANE_API_KEY=$null
    $env:OPENAI_ADMIN_KEY=$null
    $env:PERSONAL_DC_HOME=$null
    if($clear){[Array]::Clear($clear,0,$clear.Length)}
    [Array]::Clear($encrypted,0,$encrypted.Length)
    $key=$null
}
