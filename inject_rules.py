import re
import os

file_path = "sr_top500_banlist.conf"

# 你的自定义规则块
custom_rules = """
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
"""

# 需要在原上游中精准删除的域名列表
domains_to_remove = [
    "binancezh.cc",
    "www.binance.top",
    "binance.org",
    "binancezh.biz",
    "binance-cn.com",
    "binance.com",
    "binancezh.io"
]

if not os.path.exists(file_path):
    print(f"找不到文件: {file_path}")
    exit(1)

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# ==========================================
# 1. 过滤掉旧的 Binance 代理规则
# ==========================================
lines = content.split('\n')
filtered_lines = []
for line in lines:
    # 忽略注释行。通过前后加逗号(如 ,binance.com,) 实现精准匹配，防止误伤含有该字符串的其他域名
    if not line.strip().startswith('#') and any(f",{domain}," in line for domain in domains_to_remove):
        continue  # 命中需要删除的域名，直接跳过，不加入最终文件
    filtered_lines.append(line)

content = '\n'.join(filtered_lines)

# ==========================================
# 2. 插入自定义规则块
# ==========================================
# 匹配你指定的锚点注释区域
anchor = r'(\[Rule\]\s*#\s*# 黑名单中包含了 GFWList 中定义的无法访问的网站，剩下的网站直连。\s*# 未包含广告过滤\s*#)'

if re.search(anchor, content):
    content = re.sub(anchor, r'\1\n' + custom_rules.strip() + '\n', content, count=1)
else:
    # 兜底防错：如果原作者修改了注释，就直接紧贴在 [Rule] 下方插入
    content = content.replace('[Rule]', '[Rule]\n' + custom_rules.strip() + '\n', 1)

# ==========================================
# 3. 追加 MITM hostname
# ==========================================
# 查找包含 *.googlevideo.com 的行，并在其后追加目标域名
content = re.sub(
    r'(hostname\s*=\s*.*?\*\.googlevideo\.com)', 
    r'\1,*.ddgksf2013.top', 
    content, 
    flags=re.IGNORECASE
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("规则修改并注入成功！")