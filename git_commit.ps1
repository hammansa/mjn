param(
    [string]$Message = "Update project",
    [switch]$All,
    [string]$RemoteUrl,
    [switch]$Push
)

Set-StrictMode -Version Latest
function Write-ErrAndExit($msg){ Write-Host $msg -ForegroundColor Red; exit 1 }

if (-not (Get-Command git -ErrorAction SilentlyContinue)){
    Write-ErrAndExit "Git이 시스템에 설치되어 있지 않습니다. 먼저 Git을 설치하세요."
}

# Initialize repo if needed
if (-not (git rev-parse --is-inside-work-tree 2>$null)){
    $proc = Start-Process git -ArgumentList 'init' -NoNewWindow -Wait -PassThru -RedirectStandardError stderr.txt -RedirectStandardOutput stdout.txt
    if ($proc.ExitCode -ne 0){
        $err = Get-Content stderr.txt -Raw -ErrorAction SilentlyContinue
        Write-ErrAndExit ("git init 실패: " + $err)
    }
    git checkout -b main 2>$null
    Write-Host "Initialized new git repository and created 'main' branch."
}

if ($RemoteUrl){
    try{
        $existing = git remote get-url origin 2>$null
        if ($existing){
            git remote set-url origin $RemoteUrl
            Write-Host "Updated origin to $RemoteUrl"
        } else {
            git remote add origin $RemoteUrl
            Write-Host "Added origin $RemoteUrl"
        }
    } catch { Write-Host "원격 추가/설정 중 오류: $_" -ForegroundColor Yellow }
}

# Default file list (only stage these unless -All is set)
$files = @(
    'static/logo.svg',
    'static/favicon.svg',
    'static/logo.png',
    'templates/app_index.html',
    'templates/admin.html',
    'templates/expert.html',
    'templates/expert_upload.html',
    'templates/login.html',
    'templates/register.html',
    'landing.html',
    'index.html',
    '.gitignore',
    'tools/render_logo.py'
)

if ($All){
    git add -A
} else {
    $toAdd = @()
    foreach ($f in $files){ if (Test-Path $f){ $toAdd += $f } }
    if ($toAdd.Count -eq 0){ Write-Host "스테이징할 파일이 없습니다 (목록에 해당 파일이 없습니다). Use -All to add all changes."; exit 0 }
    git add -- $toAdd
}

$status = git status --porcelain
if (-not $status){ Write-Host "커밋할 변경사항이 없습니다."; exit 0 }

# Commit (handle messages with spaces correctly)
$commitOutput = & git commit -m "$Message" 2>&1
if ($LASTEXITCODE -ne 0){
    Write-ErrAndExit ("커밋 실패: " + ($commitOutput -join "`n"))
}
Write-Host "Committed: $Message"

if ($Push){
    try{
        $pushOutput = & git push -u origin main 2>&1
        if ($LASTEXITCODE -ne 0){
            Write-ErrAndExit ("푸시 실패: " + ($pushOutput -join "`n"))
        }
        Write-Host "Pushed to origin/main"
    } catch { Write-ErrAndExit "푸시 실패: $_" }
}

Write-Host "완료." -ForegroundColor Green
