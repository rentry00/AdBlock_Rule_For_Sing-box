# https://github.com/SagerNet/sing-geosite/blob/main/.github/release-rule-set.sh

#!/bin/bash

set -e -o pipefail


wget https://github.com/SagerNet/sing-box/releases/download/v1.11.15/sing-box-1.11.15-linux-amd64.tar.gz
tar -zxvf sing-box-1.11.15-linux-amd64.tar.gz

sing-box-1.11.15-linux-amd64/sing-box rule-set compile --output adblock_reject2.srs adblock_reject2.json

git init
git config --global user.name 'github-actions'  # 配置提交用户名
git config --global user.email 'github-actions@github.com'  # 配置提交邮箱
git remote add origin https://github-action:$GITHUB_TOKEN@github.com/rentry00/AdBlock_Rule_For_Sing-box.git
git branch -M main
git add .
git commit -m 'Update adblock_reject2.srs' || git commit --allow-empty -m 'Empty commit to force push'  # 提交更改，若无更改则提交空更改
git push -f origin main
