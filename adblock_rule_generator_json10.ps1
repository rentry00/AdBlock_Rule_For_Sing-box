# Title: AdBlock_Rule_For_Sing-box
# Description: 适用于Sing-box的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-CC-BY-NC-SA 4.0


# 定义广告过滤器URL列表
$urlList = @(
"https://github.com/spydisec/spydithreatintel/raw/refs/heads/main/domainlist/ads/advtracking_domains.txt",
"https://github.com/spydisec/spydithreatintel/raw/refs/heads/main/domainlist/malicious/domain_ioc_maltrail_new.txt",
"https://github.com/spydisec/spydithreatintel/raw/refs/heads/main/domainlist/spam/spamscamabuse_domains.txt",
"https://github.com/spydisec/spydithreatintel/raw/refs/heads/main/iplist/filtered_malicious_iplist.txt",
"https://github.com/FiltersHeroes/KADhosts/raw/refs/heads/master/KADomains.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/abuse/blocklistproject/hosts.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/amp/ente-dev/google-amp-hosts.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/anime/main.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/crypto/cryptojacking/firebog/Prigent/Crypto.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/dead-domains/jarelllama/dead-domains.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/drugs/blocklistproject/drugs.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/FadeMind/add-2o7Net.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/extensions/MajkiIT/adguard-host.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/MajkiIT/easy-privacy-host.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/deathbybandaid/CountryCodesLists-France.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/deathbybandaid/ParsedBlacklists-EasyList-Liste-FR.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/deathbybandaid/ParsedBlacklists-EasyList.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/justdomains/adguarddns-justdomains.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/extensions/notracking/hostnames.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/extensions/r-a-y/AdguardMobileSpyware.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/fakenews/StevenBlack/hosts.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/fakenews/marktron/hosts.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/fraud/blocklistproject/hosts.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/gambling/sefinek.hosts2.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/hate-and-junk/sefinek.hosts.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/AssoEchap/stalkerware-indicators.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/malicious/RPiList/Malware.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/ShadowWhisperer/malware.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/Spam404/main-blacklist.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/bigdargon/hostsVN.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/malicious/blocklistproject/malware.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/digitalside/latestdomains.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/disconnectme/simple-malvertising.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/malware-filter/urlhaus-filter-hosts-online.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/malicious/quidsup/notrack-malware.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/other/StevenBlack/fakenews-gambling-porn.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/other/polish-blocklists/MajkiIT/hostfile.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/other/polish-blocklists/PolishFiltersTeam/KADhosts.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/other/polish-blocklists/cert.pl/domains-hosts.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/phishing/Dogino/Discord-Phishing-URLs-phishing.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/phishing/RPiList/Phishing-Angriffe.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/phishing/blocklistproject/phishing.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/phishing/phishing.army/blocklist-extended.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/piracy/sefinek.hosts.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/porn/4skinSkywalker/hosts.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/porn/ShadowWhisperer/adult.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/porn/Sinfonietta/pornography-hosts.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/porn/StevenBlack/porn.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/porn/blocklistproject/porn.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/porn/chadmayfield/pi-blocklist-porn-all.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/porn/oisd/nsfw.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/porn/sefinek.hosts2.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/ransomware/blocklistproject/ransomware.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/redirect/blocklistproject/redirect.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/scam/Dogino/Discord-Phishing-URLs-scam.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/scam/ShadowWhisperer/scam.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/scam/blocklistproject/scam.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/scam/durablenapkin/scamblocklist.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/scam/jarelllama/scam.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/scam/sefinek.hosts.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/booth.pm.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/scam/jarelllama/scam.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/booth.pm.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/esport.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/lgbtqplus.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/gamebanana.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/lgbtqplus2.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/ometv.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/patreon.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/sites/pinterest.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/pixiv.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/riotgames.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/shopping.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/social-media.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/streaming-media.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/youtube-extended.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/blob/main/blocklists/generated/adguard/sites/youtube.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/social/facebook.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/social/instagram.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/social/snapchat.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/social/tiktok.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/social/twitter.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/spam/FadeMind/add-Spam.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/spam/RPiList/spam-mails.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/spam/stopforumspam/toxic-domains-whole.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/suspicious/FadeMind/add-Risk.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/suspicious/firebog/w3kbl.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/0Zinc/easyprivacy.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/MajkiIT/adguard-mobile-host.fork.txt",
"https://github.com/sefinek/Sefinek-Blocklist-Collection/raw/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/ShadowWhisperer/tracking.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/ente-dev/tv.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/frogeye/firstparty-trackers-hosts.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/neodevpro/host.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/tracking-and-telemetry/quidsup/trackers-hosts.fork.txt",
"https://raw.githubusercontent.com/sefinek/Sefinek-Blocklist-Collection/refs/heads/main/blocklists/generated/adguard/useless-websites/jarelllama/parked-domains.fork.txt"


)

# 日志文件路径
$logFilePath = "$PSScriptRoot/adblock_log.txt"

# 创建两个HashSet来存储唯一的规则和排除的域名
$uniqueRules = [System.Collections.Generic.HashSet[string]]::new()
$excludedDomains = [System.Collections.Generic.HashSet[string]]::new()

# 创建WebClient对象用于下载规则
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

# DNS规范验证函数
function Is-ValidDNSDomain($domain) {
    if ($domain.Length -gt 253) { return $false }
    $labels = $domain -split "\."
    foreach ($label in $labels) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch "^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$") {
            return $false
        }
    }
    $tld = $labels[-1]
    if ($tld -notmatch "^[a-zA-Z]{2,}$") { return $false }
    return $true
}

foreach ($url in $urlList) {
    Write-Host "正在处理: $url"
    Add-Content -Path $logFilePath -Value "正在处理: $url"
    try {
        # 读取并拆分内容为行
        $content = $webClient.DownloadString($url)
        $lines = $content -split "`n"

        foreach ($line in $lines) {
            # 直接处理以 @@ 开头的规则，提取域名并加入白名单
            if ($line.StartsWith('@@')) {
                $domains = $line -replace '^@@', '' -split '[^\w.-]+'
                foreach ($domain in $domains) {
                    if (-not [string]::IsNullOrWhiteSpace($domain) -and $domain -match '[\w-]+(\.[[\w-]+)+') {
                        $excludedDomains.Add($domain.Trim()) | Out-Null
                    }
                }
            }
            else {
                # 匹配 Adblock/Easylist 格式的规则
                if ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Hosts 文件格式的 IPv4 规则
                elseif ($line -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Hosts 文件格式的 IPv6 规则（以 ::1 或 :: 开头）
                elseif ($line -match '^::(1)?\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[2]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Dnsmasq address=/域名/格式的规则
                elseif ($line -match '^address=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配 Dnsmasq server=/域名/的规则
                elseif ($line -match '^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 匹配通配符规则
                elseif ($line -match '^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
                # 处理纯域名行
                elseif ($line -match '^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$') {
                    $domain = $Matches[1]
                    $uniqueRules.Add($domain) | Out-Null
                }
            }
        }
    }
    catch {
        Write-Host "处理 $url 时出错: $_"
        Add-Content -Path $logFilePath -Value "处理 $url 时出错: $_"
    }
}

# 在写入文件之前进行DNS规范验证
$validRules = [System.Collections.Generic.HashSet[string]]::new()
$validExcludedDomains = [System.Collections.Generic.HashSet[string]]::new()

foreach ($domain in $uniqueRules) {
    if (Is-ValidDNSDomain($domain)) {
        $validRules.Add($domain) | Out-Null
    }
}

foreach ($domain in $excludedDomains) {
    if (Is-ValidDNSDomain($domain)) {
        $validExcludedDomains.Add($domain) | Out-Null
    }
}

# 排除所有白名单规则中的域名
$finalRules = $validRules | Where-Object { -not $validExcludedDomains.Contains($_) }

# 统计生成的规则条目数量
$ruleCount = $finalRules.Count

# 将域名按字母顺序排序
$sortedDomains = $finalRules | Sort-Object

# 将规则格式化为JSON格式
$jsonContent = @{
    version = 1  # 设置 version 为 1
    rules = @(
        @{
            domain= $sortedDomains
        }
    )
}

# 转换为带紧凑缩进的JSON格式
$jsonFormatted = $jsonContent | ConvertTo-Json -Depth 10 | ForEach-Object { $_.Trim() }

# 定义输出文件路径
$outputPath = "$PSScriptRoot/adblock_reject10.json"
$jsonFormatted | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"

Pause