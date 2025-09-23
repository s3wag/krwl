#!/bin/bash

set -e

echo "[+] Updating packages..."
sudo apt update && sudo apt-get update
sudo apt install -y golang amass jq whatweb nuclei
pipx install uro

echo "[+] Installing Go tools..."

go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/incogbyte/shosubgo@latest
go install github.com/gwen001/github-subdomains@latest
go install github.com/gwen001/gitlab-subdomains@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/s0md3v/smap/cmd/smap@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/channyein1337/jsleak@latest
go install github.com/glebarez/cero@latest
go install github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns.git ~/.gf
go install github.com/tomnomnom/qsreplace@latest
go install github.com/ferreiraklet/airixss@latest
go install github.com/takshal/freq@latest

sudo cp -r ~/go/bin/* /usr/local/bin/

