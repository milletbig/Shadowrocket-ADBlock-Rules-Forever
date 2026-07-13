import re
import os
import urllib.request
import urllib.parse
import json

# 版本信息
VERSION = "1.1.002"
file_path = "sr_top500_banlist.conf"

# 自定义规则块
custom_rules = """
# ==========================================
# 👇👇👇 自定义规则开始 👇👇👇
# ==========================================

# 拦截 STUN 流量 (防止 WebRTC 真实 IP 泄露)
# 拦截 STUN 协议的默认常用 UDP 端口 (3478 为标准 STUN，5349 为 TLS STUN)
DST-PORT,3478,REJECT
DST-PORT,5349,REJECT
# 拦截包含 stun 关键词的主流公共探测服务器域名
DOMAIN-KEYWORD,stun,REJECT

RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/AppleProxy/AppleProxy.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/iCloud/iCloud.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/iCloudPrivateRelay/iCloudPrivateRelay.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Duolingo/Duolingo.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/PayPal/PayPal.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Twitter/Twitter.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Google/Google.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/YouTube/YouTube.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Notion/Notion.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/TikTok/TikTok.list,PROXY
RULE-SET,https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Shadowrocket/OneDrive/OneDrive.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Binance/Binance.list,DIRECT

# 疑似Binance域名走直连
DOMAIN-SUFFIX,binancezh.cc,DIRECT
DOMAIN-SUFFIX,www.binance.top,DIRECT
DOMAIN-SUFFIX,binance.org,DIRECT
DOMAIN-SUFFIX,binancezh.biz,DIRECT
DOMAIN-SUFFIX,binance-cn.com,DIRECT
DOMAIN-SUFFIX,binance.com,DIRECT
DOMAIN-SUFFIX,binancezh.io,DIRECT
# 疑似Binance美国域名走代理
DOMAIN-SUFFIX,binance.us,PROXY

# Bitwarden
DOMAIN-SUFFIX,bitwarden.com,PROXY

# e充电 去广告
DOMAIN-SUFFIX,flytechtj.com,REJECT
DOMAIN-SUFFIX,puata.info,REJECT
# e充电 隐私防追踪 & 崩溃日志上报
DOMAIN-SUFFIX,yxyylog.echargenet.com,REJECT
DOMAIN-SUFFIX,adash-evone.echargenet.com,REJECT
DOMAIN,pro.bugly.qq.com,REJECT

# Apple Push / APNs
DOMAIN-SUFFIX,push.apple.com,PROXY
DOMAIN-SUFFIX,gateway.push.apple.com,PROXY
DOMAIN-SUFFIX,api.push.apple.com,PROXY
DOMAIN-SUFFIX,sandbox.push.apple.com,PROXY
# Apple Intelligence / Siri / Relay
DOMAIN-SUFFIX,apple-relay.akamaized.net,PROXY
DOMAIN-SUFFIX,apple-relay.apple.com,PROXY
DOMAIN-SUFFIX,apple-relay.cloudflare.com,PROXY
DOMAIN-SUFFIX,apple-relay.fastly-edge.com,PROXY
DOMAIN-SUFFIX,apple-relay.mask.apple-dns.net,PROXY
# Apple services that may need PROXY
DOMAIN,www-cdn.icloud.com.akadns.net,PROXY
DOMAIN-SUFFIX,aaplimg.com,PROXY
DOMAIN-SUFFIX,apple-cloudkit.com,PROXY
DOMAIN-SUFFIX,apple.co,PROXY
DOMAIN-SUFFIX,apple.com,PROXY
DOMAIN-SUFFIX,apple.news,PROXY
DOMAIN-SUFFIX,appstore.com,PROXY
DOMAIN-SUFFIX,cdn-apple.com,PROXY
DOMAIN-SUFFIX,icloud-content.com,PROXY
DOMAIN-SUFFIX,icloud.com,PROXY
DOMAIN-SUFFIX,me.com,PROXY
DOMAIN-SUFFIX,mzstatic.com,PROXY
# Mainland China Apple services keep direct
DOMAIN-SUFFIX,apple.com.cn,DIRECT
DOMAIN-SUFFIX,icloud.com.cn,DIRECT
DOMAIN,captive.apple.com,DIRECT

# ==========================================
# 👆👆👆 自定义规则结束 👆👆👆
# ==========================================
"""

# 1. 需要在原上游中精准删除的域名列表
domains_to_remove = [
    "binancezh.cc",
    "www.binance.top",
    "binance.org",
    "binancezh.biz",
    "binance-cn.com",
    "binance.com",
    "binancezh.io",
    "binance.us"
]

# 2. 需要在原上游中精准删除的其他规则/链接列表
rules_to_remove = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AppleNews/AppleNews.list"
]

if not os.path.exists(file_path):
    print(f"找不到文件: {file_path}")
    exit(1)

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# ==========================================
# 1. 过滤掉旧的规则（Binance 和 AppleNews）
# ==========================================
lines = content.split('\n')
filtered_lines = []
for line in lines:
    if not line.strip().startswith('#'):
        # 检查是否命中要删除的 Binance 域名
        if any(f",{domain}," in line for domain in domains_to_remove):
            continue  
            
        # 检查是否命中要删除的具体 RULE-SET 链接
        if any(rule in line for rule in rules_to_remove):
            continue  
            
    filtered_lines.append(line)

content = '\n'.join(filtered_lines)

# ==========================================
# 2. 插入自定义规则块
# ==========================================
anchor = r'(\[Rule\]\s*#\s*# 黑名单中包含了 GFWList 中定义的无法访问的网站，剩下的网站直连。\s*# 未包含广告过滤\s*#)'

if re.search(anchor, content):
    content = re.sub(anchor, r'\1\n' + custom_rules.strip() + '\n', content, count=1)
else:
    # 兜底防错
    content = content.replace('[Rule]', '[Rule]\n' + custom_rules.strip() + '\n', 1)

# ==========================================
# 2.5 统一策略动作大小写
# ==========================================
# [ \t]* 只匹配空格和制表符，不匹配换行符。
# (?=\r|\n|$|#) 是前瞻断言，只判断后面是不是换行或注释，但不去替换它们。
content = re.sub(r',[ \t]*Proxy[ \t]*(?=\r|\n|$|#)', r',PROXY', content, flags=re.IGNORECASE)
content = re.sub(r',[ \t]*direct[ \t]*(?=\r|\n|$|#)', r',DIRECT', content, flags=re.IGNORECASE)

# ==========================================
# 3. 追加 MITM hostname
# ==========================================
content = re.sub(
    r'(hostname\s*=\s*.*?\*\.googlevideo\.com)', 
    r'\1,*.ddgksf2013.top,hub.kelee.one,gs-loc.apple.com,gs-loc-cn.apple.com,bluedot.is.autonavi.com,bluedot.is.autonavi.com.gds.alibabadns.com',
    content, 
    flags=re.IGNORECASE
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"版本 {VERSION}: 规则修改、注入及大小写规范化(已修复换行)成功！")

# ==========================================
# 4. 发送 PushDeer 通知
# ==========================================
def send_pushdeer():
    pushkey = os.environ.get("PUSHDEER_KEY")
    if not pushkey:
        print("未配置 PUSHDEER_KEY 环境变量，跳过发送通知。")
        return
    
    url = "https://api2.pushdeer.com/message/push"
    # 通知标题和内容
    data = urllib.parse.urlencode({
        'pushkey': pushkey,
        'text': f'✅ Shadowrocket 规则同步成功 (v{VERSION})',
        'desp': '上游规则已拉取，且自定义规则已注入。'
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            if result.get('code') == 0:
                print("PushDeer 通知发送成功！")
            else:
                print(f"PushDeer 通知发送异常: {result}")
    except Exception as e:
        print(f"PushDeer 通知发送失败: {e}")

# 执行发送
send_pushdeer()