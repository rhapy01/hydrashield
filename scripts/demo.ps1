$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path "$PSScriptRoot\..\hydradb-data\store" | Out-Null
New-Item -ItemType Directory -Force -Path "$PSScriptRoot\..\hydradb-data\cache" | Out-Null
Set-Location "$PSScriptRoot\.."
docker compose up --build
