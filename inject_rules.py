import re
import os

file_path = "sr_top500_banlist.conf"

# 自定义规则块
custom_rules = """
# ==========================================
# 👇👇👇 自定义规则开始 👇👇👇
# ==========================================
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/AppleProxy/AppleProxy.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Duolingo/Duolingo.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/PayPal/PayPal.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Twitter/Twitter.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Google/Google.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/YouTube/YouTube.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Notion/Notion.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Binance/Binance.list,direct

# 疑似Binance域名走直连
DOMAIN-SUFFIX,binancezh.cc,direct
DOMAIN-SUFFIX,www.binance.top,direct
DOMAIN-SUFFIX,binance.org,direct
DOMAIN-SUFFIX,binancezh.biz,direct
DOMAIN-SUFFIX,binance-cn.com,direct
DOMAIN-SUFFIX,binance.com,direct
DOMAIN-SUFFIX,binancezh.io,direct
# 疑似Binance美国域名走代理
DOMAIN-SUFFIX,binance.us,Proxy
# Bitwarden
DOMAIN-SUFFIX,bitwarden.com,Proxy
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
    "binancezh.io"
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
            continue  # 跳过，不写入新文件
            
        # 检查是否命中要删除的具体 RULE-SET 链接
        if any(rule in line for rule in rules_to_remove):
            continue  # 跳过，不写入新文件
            
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
# 3. 追加 MITM hostname
# ==========================================
content = re.sub(
    r'(hostname\s*=\s*.*?\*\.googlevideo\.com)', 
    r'\1,*.ddgksf2013.top', 
    content, 
    flags=re.IGNORECASE
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("规则修改并注入成功！")