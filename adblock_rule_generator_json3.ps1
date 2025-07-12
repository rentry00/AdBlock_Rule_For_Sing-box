# Title: AdBlock_Rule_For_Sing-box
# Description: 适用于Sing-box的域名拦截列表，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-CC-BY-NC-SA 4.0

# 定义广告过滤器URL列表
$urlList = @(
"https://raw.githubusercontent.com/ghostnetic/adblock-filter-compiler/refs/heads/main/blocklist.txt",
"https://raw.githubusercontent.com/keanugithub/sp-filters/refs/heads/main/blocklists.txt",
"https://raw.githubusercontent.com/peter9811/ad_filter2hosts/refs/heads/main/hosts_filtered.txt",
"https://raw.githubusercontent.com/1stfine/open_clash/master/rule_provider/rule_porn.yaml",
"https://raw.githubusercontent.com/4skinSkywalker/Anti-Porn-HOSTS-File/refs/heads/master/HOSTS.txt",
"https://raw.githubusercontent.com/ajayyy/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/alexsannikov/adguardhome-filters/master/porn.txt",
"https://raw.githubusercontent.com/ameshkov/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt",
"https://raw.githubusercontent.com/brijrajparmar27/host-sources/master/Porn/hosts",
"https://raw.githubusercontent.com/Castle67/CastleAds/main/extensions/porn/sinfonietta/hosts.txt",
"https://raw.githubusercontent.com/Castle67/CastleAds/main/NakedSite.lst",
"https://raw.githubusercontent.com/DHCW-Operational-Security/TI/master/BlockedDomains_Porn.txt",
"https://raw.githubusercontent.com/diwasatreya/bad-websites/master/separated/nsfw.json",
"https://raw.githubusercontent.com/edmond-nader/MyPiHoleLists/main/PiPornList.txt",
"https://raw.githubusercontent.com/edwdch/domain-yaml-community/master/yaml/category-porn.txt",
"https://raw.githubusercontent.com/elbkr/bad-websites/main/separated/nsfw.json",
"https://raw.githubusercontent.com/emiliodallatorre/adult-hosts-list/main/list.txt",
"https://raw.githubusercontent.com/funilrys/pornhosts/master/submit_here/hosts.txt",
"https://raw.githubusercontent.com/go2engineering/pihole-blocklists/main/pihole_blocklist_adult.list",
"https://raw.githubusercontent.com/insightbrowser/scripts/master/top_1m_porn_hosts.txt",
"https://raw.githubusercontent.com/LittleCordines/pfsense-hosts-file/master/PornBlocklists",
"https://raw.githubusercontent.com/lonecale/Rules/master/Geosite/rules/category-porn.txt",
"https://raw.githubusercontent.com/madcow05/Scam-Blocklist/master/lists/adblock/nsfw.txt",
"https://raw.githubusercontent.com/madi10/MANTANKODE/master/AdGuard/pornlist.txt",
"https://raw.githubusercontent.com/moose84/list/master/listaPI.txt",
"https://raw.githubusercontent.com/mssvpn/block/master/porn.txt",
"https://raw.githubusercontent.com/mssvpn/domain-list-community/master/data/category-porn",
"https://raw.githubusercontent.com/mullvad/dns-blocklists/main/lists/relay/adult/oisd-nsfw",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/alexsannikov-pornlist.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all1.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all2.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all3.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/porn-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/fraud-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/abuse-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/malware-filter.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/spam/spamscamabuse_domains.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/malicious/domain_ioc_maltrail_new.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/ads/advtracking_domains.txt",
"https://raw.githubusercontent.com/miriquidi/domain-blocklists/refs/heads/main/block.txt",
"https://raw.githubusercontent.com/sol1/blocklist-domains/refs/heads/main/outputs/hosts.txt",
"https://raw.githubusercontent.com/person9876/blocklist/refs/heads/main/domainlist.txt",
"https://raw.githubusercontent.com/dmachard/blocklist-domains/data/hosts.txt"

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

# 对规则进行排序并添加前缀和后缀
$formattedRules = $finalRules | Sort-Object | ForEach-Object {
    $quote = "`""
    "$quote" + "$_$quote,"
}


# 移除最后一条规则的逗号
if ($formattedRules.Count -gt 0) {
    $formattedRules[-1] = $formattedRules[-1].TrimEnd(',')
}


# 统计生成的规则条目数量
$ruleCount = $finalRules.Count




# 获取当前时间并转换为东八区时间
$generationTime = (Get-Date).ToUniversalTime().AddHours(8).ToString("yyyy-MM-dd HH:mm:ss")

# 创建文本格式的字符串
$textContent = @"
# Title: AdBlock_Rule_For_Sing-box
# Description: 适用于Sing-box的域名拦截列表，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-CC-BY-NC-SA 4.0
# Generated on: $generationTime
# Generated AdBlock rules
# Total entries: $ruleCount

$($formattedRules -join "`n")
"@

# 定义输出文件路径
$outputPath = "$PSScriptRoot/adblock_reject3.json"
$textContent | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"
