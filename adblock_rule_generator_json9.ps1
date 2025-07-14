# Title: AdBlock_Rule_For_Sing-box
# Description: 适用于Sing-box的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-CC-BY-NC-SA 4.0


# 定义广告过滤器URL列表
$urlList = @(
"https://github.com/NotaInutilis/Super-SEO-Spam-Suppressor/raw/refs/heads/main/adblock.txt",
"https://github.com/kveld9/PiSolid/raw/refs/heads/main/pisolid-nsfw.txt",
"https://github.com/kveld9/PiSolid/raw/refs/heads/main/pisolid-ultra.txt",
"https://github.com/kveld9/PiSolid/raw/refs/heads/main/pisolid.txt",
"https://github.com/kdenhartog/eth-phish-filterlist/raw/refs/heads/main/filterlist/eth-phishing-list.filter",
"https://easylist.to/easylist/easylist.txt",
"https://github.com/SystemJargon/filters/raw/refs/heads/main/porn.txt",
"https://github.com/SystemJargon/filters/raw/refs/heads/main/restrict-bypass-user_child.txt",
"https://github.com/SystemJargon/filters/raw/refs/heads/main/restrict-bypass.txt",
"https://github.com/SystemJargon/filters/raw/refs/heads/main/telemetry.txt",
"https://github.com/SystemJargon/filters/raw/refs/heads/main/ads.txt",
"https://github.com/zhiyuan1i/adblock_list/raw/refs/heads/master/adblock_privacy.txt",
"https://github.com/egetaken/turkish-blocklist/raw/refs/heads/main/hosts",
"https://github.com/DevShubam/Filters/raw/refs/heads/main/gambling/gambling-combined.txt",
"https://raw.githubusercontent.com/Lky777/MWCP/refs/heads/main/rules/adservers.txt",
"https://raw.githubusercontent.com/Lky777/MWCP/refs/heads/main/rules/supple.txt",
"https://raw.githubusercontent.com/Lky777/MWCP/refs/heads/main/rules/hosts",
"https://raw.githubusercontent.com/Lky777/MWCP/refs/heads/main/rules/MobiList.txt",
"https://raw.githubusercontent.com/stonecrusher/filterlists-pihole/master/fakenews-de-ph.txt",
"https://raw.githubusercontent.com/stonecrusher/filterlists-pihole/master/watchlist-internet-ph.txt",
"https://raw.githubusercontent.com/stonecrusher/filterlists-pihole/master/pseudowissenschaft-ph.txt",
"https://raw.githubusercontent.com/stonecrusher/filterlists-pihole/master/VScom_fakeshops-ph.txt",
"https://raw.githubusercontent.com/stonecrusher/filterlists-pihole/master/VScom_streaming-ph.txt",
"https://raw.githubusercontent.com/stonecrusher/filterlists-pihole/master/VSde_problematic_onlineshops-ph.txt",
"https://easylist.to/easylist/easyprivacy.txt",
"https://github.com/TheEndBoss-101-Web/Adblock-Rules/raw/refs/heads/main/ADBLOCK_RULE_COLLECTION.txt",
"https://github.com/TheEndBoss-101-Web/Adblock-Rules/raw/refs/heads/main/ADBLOCK_RULE_COLLECTION_DNS.txt",
"https://github.com/TheEndBoss-101-Web/Adblock-Rules/raw/refs/heads/main/ADBLOCK.txt",
"https://github.com/TheEndBoss-101-Web/Adblock-Rules/raw/refs/heads/main/ADBLOCK_RULE_COLLECTION_DOMAIN.txt",
"https://github.com/TheEndBoss-101-Web/Adblock-Rules/raw/refs/heads/main/ADBLOCK_RULE_COLLECTION_HOST_IPV4.txt",
"https://github.com/TheEndBoss-101-Web/Adblock-Rules/raw/refs/heads/main/ADBLOCK_RULE_COLLECTION_HOST_IPV6.txt",
"https://github.com/mmhhhhh/adblock-rules-aggregator/raw/refs/heads/main/adblock_reject.list",
"https://github.com/execute-darker/darkerADS/raw/refs/heads/main/data/rules/adblock.txt",
"https://raw.githubusercontent.com/Chaniug/FilterFusion/main/dist/adblock-main.txt",
"https://github.com/psychosispy/adblock/raw/refs/heads/main/ads.txt",
"https://github.com/Cats-Team/AdRules/blob/script/rules/jiekouAD.txt",
"https://raw.githubusercontent.com/twcau/AdblockRules/master/MurdochList",
"https://raw.githubusercontent.com/twcau/AdblockRules/master/CustomSonyTVList",
"https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
"https://raw.githubusercontent.com/twcau/AdblockRules/master/CytroxList",
"https://github.com/cbuijs/adblocks/raw/refs/heads/main/ultimate.adblock.txt",
"https://github.com/caidiekeji/adguard-auto-rules/raw/refs/heads/main/adguard-rules.txt",
"https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-all.ipv4",
"https://github.com/cuongdt1994/Block-Phising-Crypto-Domains/raw/refs/heads/main/lists/daily",
"https://github.com/security-alliance/blocklists/raw/refs/heads/main/domain.txt",
"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/trackers.list",
"https://lists.blocklist.de/lists/all.txt",
"https://github.com/Ultimate-Hosts-Blacklist/www.blocklist.de/raw/refs/heads/master/output/domains.list/splitted/ACTIVE",
"https://github.com/Ultimate-Hosts-Blacklist/www.blocklist.de/raw/refs/heads/master/output/domains.list/splitted/INACTIVE",
"https://easylist.to/easylist/fanboy-social.txt",
"https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/inbound.txt",
"https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/outbound.txt",
"https://raw.githubusercontent.com/sjhgvr/oisd/main/abp_nsfw.txt",
"https://raw.githubusercontent.com/mullvad/dns-blocklists/main/lists/relay/adult/oisd-nsfw",
"https://raw.githubusercontent.com/alexsannikov/adguardhome-filters/master/porn.txt",
"https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",
"https://raw.githubusercontent.com/edwdch/domain-yaml-community/master/yaml/category-porn.txt",
"https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-porn",
"https://raw.githubusercontent.com/madi10/MANTANKODE/master/AdGuard/pornlist.txt",
"https://raw.githubusercontent.com/orange1688/zflow/master/url_filter/adult_url_filter_domain.txt",
"https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/porn-nl.txt",
"https://raw.githubusercontent.com/ameshkov/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/Castle67/CastleAds/main/NakedSite.lst",
"https://raw.githubusercontent.com/Castle67/CastleAds/main/extensions/porn/sinfonietta/hosts.txt",
"https://raw.githubusercontent.com/LittleCordines/pfsense-hosts-file/master/PornBlocklists",
"https://raw.githubusercontent.com/elbkr/bad-websites/main/separated/nsfw.json",
"https://raw.githubusercontent.com/mssvpn/domain-list-community/master/data/category-porn",
"https://raw.githubusercontent.com/ajayyy/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/porn-list.txt",
"https://raw.githubusercontent.com/tvpmb/easylist/master/easylist_adult/adult_specific_block.txt",
"https://raw.githubusercontent.com/OliverJAsh/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/moose84/list/master/listaPI.txt",
"https://raw.githubusercontent.com/shane-walker/easylist/master/easylist_adult/adult_specific_block.txt",
"https://raw.githubusercontent.com/brijrajparmar27/host-sources/master/Porn/hosts",
"https://raw.githubusercontent.com/emiliodallatorre/adult-hosts-list/main/list.txt",
"https://raw.githubusercontent.com/edmond-nader/MyPiHoleLists/main/PiPornList.txt",
"https://raw.githubusercontent.com/go2engineering/pihole-blocklists/main/pihole_blocklist_adult.list",
"https://raw.githubusercontent.com/pq6p41fgt6k/potential-octo-parakeet/master/porn.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/alexsannikov-pornlist.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all3.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all2.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldporn_all1.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/mhhakimpornlist.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldtop1mlist.txt",
"https://raw.githubusercontent.com/tiuxo/hosts/master/porn",
"https://raw.githubusercontent.com/rampageX/block/master/assets/sources/filter/clefspeare-pornhosts.txt",
"https://raw.githubusercontent.com/funilrys/pornhosts/master/submit_here/hosts.txt",
"https://github.com/filterpaper/blocklists/raw/refs/heads/main/nxdomains.txt",
"https://github.com/j-moriarti/pDNSf-Hosts-collection/releases/download/v1.0.0/pDNSf-hosts-part0.txt",
"https://github.com/j-moriarti/pDNSf-Hosts-collection/releases/download/v1.0.0/pDNSf-hosts-part1.txt",
"https://github.com/j-moriarti/pDNSf-Hosts-collection/releases/download/v1.0.0/pDNSf-hosts-part2.txt",
"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/malware.list",
"https://github.com/missdeer/blocklist/raw/refs/heads/master/convert/alldomains.txt",
"https://github.com/meganerasam/blocklist-v2/raw/refs/heads/master/inactive_domains_new.txt",
"https://easylist.to/easylist/fanboy-annoyance.txt",
"https://github.com/meganerasam/blocklist-v2/raw/refs/heads/master/inactive_domains.txt",
"https://github.com/DerHary/dbl_export/raw/refs/heads/main/blacklist.abp.txt",
"https://github.com/minoplhy/filters/releases/download/latest/Allowlist_adblock.txt",
"https://github.com/minoplhy/filters/releases/download/latest/ucate_adblock.txt",
"https://github.com/minoplhy/filters/releases/download/latest/Veneto_adblock.txt",
"https://github.com/KnightmareVIIVIIXC/Personal-List/raw/refs/heads/main/dns_disallowed_clients.txt",
"https://github.com/euh2/dnscrypt-blocklist/raw/refs/heads/main/dnscrypt-blocklist-domains.txt",
"https://easylist-downloads.adblockplus.org/antiadblockfilters.txt",
"https://github.com/cenk/malware-domains/raw/refs/heads/main/adblock",
"https://github.com/cenk/nrd/raw/refs/heads/main/nrd-last-60-days.txt",
"https://github.com/cenk/trcert-malware/raw/refs/heads/main/trcert-domains.txt",
"https://raw.githubusercontent.com/litetex/blocklists-unified/refs/heads/master/out/ipv6/unified.list",
"https://github.com/RPMozley/AdGuardSDNS-r-a-y/raw/refs/heads/main/adguardDNS-r-a-y.txt",
"https://easylist.to/easylistgermany/easylistgermany.txt",
"https://github.com/RPMozley/AdGuardSDNS-r-a-y/raw/refs/heads/main/AdguardDNS.txt",
"https://github.com/D34thSkull/blocklist-auto/raw/refs/heads/main/combined-blocklist.txt",
"https://raw.githubusercontent.com/raywari/ru-blocklist/refs/heads/main/data/CIDRs/CIDRs-summary.lst",
"https://github.com/JTarasovic/blocklist/raw/refs/heads/main/steven-black-unified-unbound",
"https://easylist-downloads.adblockplus.org/easylistitaly.txt",
"https://easylist-downloads.adblockplus.org/easylistdutch.txt",
"https://easylist-downloads.adblockplus.org/liste_fr.txt",
"https://easylist-downloads.adblockplus.org/easylistchina.txt",
"https://easylist-downloads.adblockplus.org/advblock.txt",
"http://stanev.org/abp/adblock_bg.txt",
"https://easylist-downloads.adblockplus.org/abpindo.txt",
"https://easylist-downloads.adblockplus.org/Liste_AR.txt",
"https://raw.githubusercontent.com/tomasko126/easylistczechandslovak/master/filters.txt",
"https://easylist-downloads.adblockplus.org/latvianlist.txt",
"https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt",
"https://easylist-downloads.adblockplus.org/dandelion_sprouts_nordic_filters%2Beasylist.txt",
"https://easylist-downloads.adblockplus.org/easylistlithuania.txt",
"https://easylist-downloads.adblockplus.org/easylistspanish.txt",
"https://easylist-downloads.adblockplus.org/easylistportuguese.txt",
"https://easylist-downloads.adblockplus.org/abpvn.txt",
"https://easylist-downloads.adblockplus.org/easylistpolish.txt",
"https://easylist-downloads.adblockplus.org/indianlist.txt",
"https://easylist-downloads.adblockplus.org/koreanlist.txt",
"https://easylist-downloads.adblockplus.org/rolist.txt",
"https://easylist-downloads.adblockplus.org/easyprivacy_nointernational.txt",
"https://easylist-downloads.adblockplus.org/easylist_noadult.txt",
"https://easylist-downloads.adblockplus.org/easylist_noelemhide.txt",
"https://easylist.to/easylist/fanboy-newsletter.txt",
"https://easylist.to/easylist/fanboy-sounds.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/main/nsfw/nsfw-personal.txt",
"https://airvpn.org/api/dns_lists/?code=pornaway_sites&style=domains",
"https://blocklistproject.github.io/Lists/adguard/porn-ags.txt",
"https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/RAW/Adult",
"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/pornblock4",
"https://nsfw.oisd.nl",
"https://github.com/DevShubam/Filters/raw/main/gambling/gambling-personal.txt",
"https://github.com/blocklistproject/Lists/raw/master/gambling.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
"https://github.com/StevenBlack/hosts/raw/master/alternates/gambling/hosts",
"https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt"


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
$outputPath = "$PSScriptRoot/adblock_reject9.json"
$jsonFormatted | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"

Pause
