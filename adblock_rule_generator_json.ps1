# Title: AdBlock_Rule_For_Sing-box
# Description: 适用于Sing-box的域名拦截规则集，每20分钟更新一次，确保即时同步上游减少误杀
# Homepage: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box
# LICENSE1: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-GPL 3.0
# LICENSE2: https://github.com/REIJI007/AdBlock_Rule_For_Sing-box/blob/main/LICENSE-CC-BY-NC-SA 4.0


# 定义广告过滤器URL列表
$urlList = @(
"https://github.com/arcestia/blocklists/raw/refs/heads/main/released/adblock.00.txt",  
"https://github.com/arcestia/blocklists/raw/refs/heads/main/released/adblock.01.txt",
"https://raw.githubusercontent.com/elliottophellia/adlist/refs/heads/main/hosts",
"https://raw.githubusercontent.com/sjhgvr/oisd/main/abp_nsfw.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/porn-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/fraud-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/abuse-filter.txt",
"https://raw.githubusercontent.com/MoisesJMorais/AdGuard-DNS-Filters/refs/heads/main/malware-filter.txt",
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
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/chadmayfieldtop1mlist.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/mhhakimpornlist.txt",
"https://raw.githubusercontent.com/nizekun/adguardhome-blocklist/main/porn-list.txt",
"https://raw.githubusercontent.com/NoGitHubForYou/yafp/master/domains_adult",
"https://raw.githubusercontent.com/NyeUsr/Blacklist/master/uBlacklist/Porn.txt",
"https://raw.githubusercontent.com/OliverJAsh/easylist/master/easylist_adult/adult_adservers.txt",
"https://raw.githubusercontent.com/orange1688/zflow/master/url_filter/adult_url_filter_domain.txt",
"https://raw.githubusercontent.com/oriay/genfilter/master/public/clash/category-porn",
"https://raw.githubusercontent.com/pq6p41fgt6k/potential-octo-parakeet/master/porn.txt",
"https://raw.githubusercontent.com/rampageX/block/master/assets/sources/filter/clefspeare-pornhosts.txt",
"https://raw.githubusercontent.com/shane-walker/easylist/master/easylist_adult/adult_specific_block.txt",
"https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",
"https://raw.githubusercontent.com/tanmoumou252/NSFWruleset/master/NSFW.yaml",
"https://raw.githubusercontent.com/tiuxo/hosts/master/porn",
"https://raw.githubusercontent.com/tvpmb/easylist/master/easylist_adult/adult_specific_block.txt",
"https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-porn",
"https://raw.githubusercontent.com/Zorus/block/master/assets/active/filter/sinfonietta-porn.txt",
"https://raw.githubusercontent.com/Zydnar/pihole_malware_blocklist/refs/heads/main/pihole_blocklist.txt",
"https://raw.githubusercontent.com/aarakh/hosts/refs/heads/master/hosts",
"https://raw.githubusercontent.com/fenixvd/pi-hole-lists/refs/heads/main/ban_list.txt",
"https://raw.githubusercontent.com/r0xd4n3t/pihole-adblock-lists/refs/heads/main/pihole_adlists.txt",
"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/refs/heads/master/newhosts-final.hosts",
"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/refs/heads/master/newhosts-final-Dual.hosts",
"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/refs/heads/master/cpbl-abp-list.txt",
"https://raw.githubusercontent.com/bongochong/CombinedPrivacyBlockLists/refs/heads/master/combined-final.cidr",
"https://raw.githubusercontent.com/jtbrough/pihole-hosts/refs/heads/main/firebog-ticked-hosts",
"https://raw.githubusercontent.com/musdx/blist/refs/heads/master/blocklist.txt",
"https://raw.githubusercontent.com/jpgpi250/piholemanual/refs/heads/master/DOH/DOHadb.txt",
"https://raw.githubusercontent.com/Bastiaantjuhh/hostfile-merge/refs/heads/main/hostfiles/blacklist.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/spam/spamscamabuse_domains.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/malicious/domain_ioc_maltrail_new.txt",
"https://raw.githubusercontent.com/spydisec/spydithreatintel/refs/heads/main/domainlist/ads/advtracking_domains.txt",
"https://raw.githubusercontent.com/miriquidi/domain-blocklists/refs/heads/main/block.txt",
"https://raw.githubusercontent.com/sol1/blocklist-domains/refs/heads/main/outputs/hosts.txt",
"https://raw.githubusercontent.com/person9876/blocklist/refs/heads/main/domainlist.txt",
"https://raw.githubusercontent.com/dmachard/blocklist-domains/data/hosts.txt",
"https://raw.githubusercontent.com/Zydnar/pihole_malware_blocklist/refs/heads/main/pihole_blocklist.txt",
"https://raw.githubusercontent.com/open-access-internet/blocklist/refs/heads/main/blocklist.txt",
"https://raw.githubusercontent.com/iaaaannn0/blocklistru/refs/heads/main/full.list",
"https://raw.githubusercontent.com/chrisjbawden/newly-registered-domains-tracker/refs/heads/main/nrd-60.txt",
"https://raw.githubusercontent.com/lolo6oT/antifilter/refs/heads/main/domains.all",
"https://raw.githubusercontent.com/Pyenb/Pi-hole-blocklist/refs/heads/main/blocklist.txt",
"https://raw.githubusercontent.com/musdx/blist/refs/heads/master/blocklist.txt",
"https://raw.githubusercontent.com/btogxx/domains-rule/refs/heads/main/cache/blockhosts.txt",
"https://raw.githubusercontent.com/KEINOS/BlockList/refs/heads/main/hosts_all-in-one.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/unified/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/porn/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/fakenews/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/gambling/stevenblack-hosts.txt",
"https://raw.githubusercontent.com/cabrata/blacklist-hosts/refs/heads/main/hosts/ads-track/adguard.txt",
"https://raw.githubusercontent.com/NotaInutilis/Super-SEO-Spam-Suppressor/refs/heads/main/adblock.txt",
"https://raw.githubusercontent.com/execute-darker/darkerADS/refs/heads/main/data/rules/adblock.txt",
"https://raw.githubusercontent.com/taichikuji/youtube-ads-4-adaway/refs/heads/main/hosts",
"https://raw.githubusercontent.com/eternity5/ChinaList-For-AdguardHome/refs/heads/main/ChinaList.txt",
"https://raw.githubusercontent.com/rcz0315/AdBlock-list-backup/refs/heads/master/merged_abp_filters.txt",
"https://raw.githubusercontent.com/nero-dv/adguard_combined_lists/refs/heads/main/adguard_combined_list.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/urlparam.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/ubolist.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/moblist.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/easyrules.txt",
"https://raw.githubusercontent.com/MkQtS/MyAdList/refs/heads/main/dnsblock.txt",
"https://raw.githubusercontent.com/jhassine/server-ip-addresses/refs/heads/master/data/datacenters.txt",
"https://raw.githubusercontent.com/peter9811/ad_filter2hosts/refs/heads/main/hosts_filtered.txt",
"https://raw.githubusercontent.com/hyder365/combined-dns-list/refs/heads/master/combined.txt",
"https://raw.githubusercontent.com/HyRespt/AD-List-Merger/refs/heads/main/duplicate_addresses.txt",
"https://raw.githubusercontent.com/HyRespt/AD-List-Merger/refs/heads/main/combined_blocklist.txt",
"https://raw.githubusercontent.com/zhiyuan1i/adblock_list/refs/heads/master/adblock_privacy.txt",
"https://raw.githubusercontent.com/caleee/adguardhome_filter_list/refs/heads/main/filters/filter.txt",
"https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/refs/heads/master/blocklist",
"https://raw.githubusercontent.com/AristonPost/AdList/refs/heads/main/fake-news-hosts",
"https://raw.githubusercontent.com/az4399/ad_list/refs/heads/main/ad.txt",
"https://raw.githubusercontent.com/hululu1068/AdGuard-Rule/refs/heads/main/rule/all.txt",
"https://raw.githubusercontent.com/5whys-adblock/AdGuardHome-rules/refs/heads/main/rules/output_super.txt",
"https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/refs/heads/master/all.txt",
"https://raw.githubusercontent.com/caidiekeji/adguard-auto-rules/refs/heads/main/adguard-rules.txt",
"https://raw.githubusercontent.com/siankatabg/FuFu-AdGuard-blacklist/refs/heads/master/fufu-adguard-blacklist.txt",
"https://raw.githubusercontent.com/IMAiCool/AdGuardHome-rules/refs/heads/main/output/BlackList.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/gambling/gambling-combined-part1.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/gambling/gambling-combined.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part4.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part3.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part2.txt",
"https://raw.githubusercontent.com/DevShubam/Filters/refs/heads/main/nsfw/nsfw_combined-part1.txt",
"https://raw.githubusercontent.com/KnightmareVIIVIIXC/AIO-Firebog-Blocklists/main/lists/aiofirebog.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/485397099/e9d2ecf2-565e-4979-91a8-1806801975bb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250709%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250709T162558Z&X-Amz-Expires=1800&X-Amz-Signature=8f06cfb0b86df06f91be3a4840e1aeb1493509afcc7abce0900aaca9f08d7b5d&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DCherrygram-9.4.0-TG-11.13.0-arm64-v8a.apk&response-content-type=application%2Fvnd.android.package-archive",
"https://raw.githubusercontent.com/KnightmareVIIVIIXC/Personal-List/refs/heads/main/dns_disallowed_clients.txt",
"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
"https://raw.githubusercontent.com/aarakh/hosts/refs/heads/master/hosts",
"https://raw.githubusercontent.com/skyhigh24/BlockList/refs/heads/main/GravityExport.txt",
"https://raw.githubusercontent.com/r0xd4n3t/pihole-adblock-lists/refs/heads/main/pihole_adlists.txt",
"https://raw.githubusercontent.com/Max-Pare/pihole-adlist-merged/refs/heads/main/merged.txt",
"https://raw.githubusercontent.com/DiegoRamil/pihole-blocklist/refs/heads/main/ads.txt",
"https://media.githubusercontent.com/media/UninvitedActivity/PiHoleLists/refs/heads/main/NRD/NRD-07_All.nrd",
"https://raw.githubusercontent.com/jtbrough/pihole-hosts/refs/heads/main/firebog-ticked-hosts",
"https://raw.githubusercontent.com/musdx/blist/refs/heads/master/blocklist.txt",
"https://raw.githubusercontent.com/FreeZoneAT/pihole-blocklist/refs/heads/main/smartblock_part3.txt",
"https://raw.githubusercontent.com/FreeZoneAT/pihole-blocklist/refs/heads/main/smartblock_part2.txt",
"https://raw.githubusercontent.com/FreeZoneAT/pihole-blocklist/refs/heads/main/smartblock_part1.txt",
"https://raw.githubusercontent.com/Bastiaantjuhh/hostfile-merge/refs/heads/main/hostfiles/blacklist.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/882358246/c0dd6b55-d5a2-4520-acfd-df1b783946df?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250709%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250709T121535Z&X-Amz-Expires=1800&X-Amz-Signature=ec115f97eb3dd11623d89cb0177ef137961688bb7e3024ca6358aaa31301e695&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DPiHoleClient_1.4.0_Android.apk&response-content-type=application%2Fvnd.android.package-archive",
"https://raw.githubusercontent.com/Melting-Core-Studios/Blocklists/refs/heads/main/AdBlocking/adblock.txt",
"https://raw.githubusercontent.com/Melting-Core-Studios/Blocklists/refs/heads/main/Tracking_blocklist/full_anti_track.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/722153127/89c25b46-4c0b-458e-999f-3670e92a04ce?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250708%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250708T171417Z&X-Amz-Expires=1800&X-Amz-Signature=5ece31761b9debb27ce3e12ab9f08270ca46031b82f559c9eb2f2a239843b7cc&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DAdGuardHomeForRoot_arm64.zip&response-content-type=application%2Foctet-stream",
"https://raw.githubusercontent.com/zhiyuan1i/adblock_list/refs/heads/master/adblock_privacy.txt",
"https://raw.githubusercontent.com/zhiyuan1i/adblock_list/refs/heads/master/adblock_plus.txt",
"https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/dns.txt",
"https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/all.txt",
"https://raw.githubusercontent.com/Chaniug/FilterFusion/main/dist/adblock-main.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/gambling.txt",
"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/ultimate.txt",
"https://raw.githubusercontent.com/Aloazny/Aloazny_Adblock/main/Rules/Adblock_Chinese.txt",
"https://raw.githubusercontent.com/Aloazny/Aloazny_Adblock/main/Rules/Adblock_attach.txt",
"https://raw.githubusercontent.com/utada1stlove/adguardhome/refs/heads/main/merged_rules.txt",
"https://raw.githubusercontent.com/8680/GOODBYEADS/refs/heads/master/data/rules/allow.txt",
"https://raw.githubusercontent.com/8680/GOODBYEADS/refs/heads/master/data/rules/dns.txt",
"https://raw.githubusercontent.com/8680/GOODBYEADS/refs/heads/master/data/rules/adblock.txt",
"https://raw.githubusercontent.com/NaivG/adlist/main/extralist.txt",
"https://raw.githubusercontent.com/NaivG/adlist/main/mainlist.txt",
"https://raw.githubusercontent.com/lingeringsound/adblock_auto/main/Rules/adblock_auto.txt",
"https://raw.githubusercontent.com/bryopsida/blocklist/refs/heads/main/dns3.txt",
"https://raw.githubusercontent.com/bryopsida/blocklist/refs/heads/main/dns2.txt",
"https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt",
"https://raw.githubusercontent.com/bryopsida/blocklist/refs/heads/main/dns1.txt",
"https://raw.githubusercontent.com/bryopsida/blocklist/refs/heads/main/dns0.txt",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/371767474/535e74a2-a2b6-4a64-a411-21e13a20ba5e?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250708%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250708T114536Z&X-Amz-Expires=1800&X-Amz-Signature=70e7b51a651907151e7ce6260b3e87b15de88f245eea47a347c543b6cf581fa8&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DALLOW_DOMAIN.txt&response-content-type=application%2Foctet-stream",
"https://objects.githubusercontent.com/github-production-release-asset-2e65be/371767474/758581fb-26d3-455c-b24d-b0c878531213?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250708%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250708T113959Z&X-Amz-Expires=1800&X-Amz-Signature=657829e7798cf859c15bc4fd644ec19995071de3dbc9cc15ee0f08fce334adfb&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3DBLOCK_DOMAIN.txt&response-content-type=application%2Foctet-stream",
"https://raw.githubusercontent.com/Skiddle-ID/blocklist/refs/heads/main/situs_judi_002.txt",
"https://raw.githubusercontent.com/Skiddle-ID/blocklist/refs/heads/main/situs_judi_001.txt",
"https://raw.githubusercontent.com/Skiddle-ID/blocklist/refs/heads/main/domains_004.txt",
"https://raw.githubusercontent.com/Skiddle-ID/blocklist/refs/heads/main/domains_003.txt",
"https://raw.githubusercontent.com/Skiddle-ID/blocklist/refs/heads/main/domains_002.txt",
"https://raw.githubusercontent.com/Skiddle-ID/blocklist/refs/heads/main/domains_001.txt",
"https://raw.githubusercontent.com/SystemJargon/filters/refs/heads/main/threats.txt",
"https://raw.githubusercontent.com/SystemJargon/filters/refs/heads/main/porn.txt",
"https://raw.githubusercontent.com/SystemJargon/filters/refs/heads/main/nrds-30days.txt",
"https://raw.githubusercontent.com/SystemJargon/filters/refs/heads/main/firebog-ticklist.txt",
"https://raw.githubusercontent.com/SystemJargon/filters/refs/heads/main/core_heavy.txt",
"https://raw.githubusercontent.com/SystemJargon/filters/refs/heads/main/ads.txt",
"https://raw.githubusercontent.com/mikndotdev/domain-blacklist-api/refs/heads/master/blacklist.txt",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain13",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain12",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain11",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain10",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain09",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain08",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain07",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain06",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain05",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain03",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain04",
"https://raw.githubusercontent.com/essinghigh/blocklist-abuseipdb-compressed/refs/heads/main/abuseipdb-s100-all_compressed.ipv4",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain02",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain01",
"https://raw.githubusercontent.com/lucasdss/blockdomain/refs/heads/main/blockdomain00",
"https://raw.githubusercontent.com/cenk/bad-hosts/refs/heads/main/bad-hosts-abp",
"https://raw.githubusercontent.com/arobass/dns-blocklist/refs/heads/master/merged-dns-blocklist.txt"
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
$outputPath = "$PSScriptRoot/adblock_reject.json"
$jsonFormatted | Out-File -FilePath $outputPath -Encoding utf8

# 输出生成的有效规则总数
Write-Host "生成的有效规则总数: $ruleCount"
Add-Content -Path $logFilePath -Value "Total entries: $ruleCount"

Pause
