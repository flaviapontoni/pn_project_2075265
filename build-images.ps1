Write-Host "Building pn4-host image (iperf3 + python3) ..."
docker build -t pn4-host ./docker/pn4-host
if (-not $?) { exit 1 }
Write-Host "Done. Run 'kathara lstart' to launch the lab."
