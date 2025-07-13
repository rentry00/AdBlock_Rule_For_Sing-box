# https://github.com/SagerNet/sing-geosite/blob/main/.github/release-rule-set.sh

#!/bin/bash

set -e -o pipefail


wget https://github.com/SagerNet/sing-box/releases/download/v1.11.15/sing-box-1.11.15-linux-amd64.tar.gz
tar -zxvf sing-box-1.11.15-linux-amd64.tar.gz

sing-box-1.11.15-linux-amd64/sing-box rule-set compile --output adblock_reject2.srs adblock_reject2.json

git init
git config --local user.email "github-action@users.noreply.github.com"
git config --local user.name "GitHub Action"
git remote add origin https://github-action:$GITHUB_TOKEN@github.com/rentry00/AdBlock_Rule_For_Sing-box.git
git branch -M main
git add -f adblock_reject2.srs  # 强制添加 adblock_reject.json 文件
git commit -m 'Update adblock_reject2.srs' || git commit --allow-empty -m 'Empty commit to force push'  # 提交更改，若无更改则提交空更


