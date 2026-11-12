import re
import os
import sys
import time
import urllib.request
import urllib.parse
import json
from datetime import datetime, timedelta, timezone

# 版本信息
VERSION = "1.5.000"
file_path = "sr_top500_banlist.conf"

# 上游资源地址（与 workflow 中的下载地址保持一致，可用于通知溯源）
UPSTREAM_URL = os.environ.get(
    "UPSTREAM_URL",
    "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_top500_banlist.conf"
)

# 规则行匹配（形如 "TYPE,内容,策略"），用于条目统计与去重
rule_line = re.compile(r'^[A-Z][A-Z0-9-]*,')

# 脚本计时起点与构建时间（固定使用北京时间，精确到分钟）
START_TIME = time.perf_counter()
BUILD_TIME = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")

# 自定义规则块
custom_rules = """
# ==========================================
# 👇👇👇 自定义规则开始 👇👇👇
# ==========================================

# 拦截 STUN 流量 (防止 WebRTC 真实 IP 泄露)
# 仅拦截已知的公共 STUN 探测服务器域名；
# 不再按 DST-PORT 3478/5349 全局拦截，也不再使用 DOMAIN-KEYWORD,stun 宽匹配，
# 避免误伤 FaceTime / 微信语音等依赖 ICE 打洞的正常 UDP 流量。
DOMAIN-SUFFIX,stun.l.google.com,REJECT
DOMAIN-SUFFIX,stun1.l.google.com,REJECT
DOMAIN-SUFFIX,stun2.l.google.com,REJECT
DOMAIN-SUFFIX,stun3.l.google.com,REJECT
DOMAIN-SUFFIX,stun4.l.google.com,REJECT
DOMAIN-SUFFIX,stun.services.mozilla.com,REJECT
DOMAIN-SUFFIX,stunserver.stunprotocol.org,REJECT
DOMAIN-SUFFIX,stun.browserleaks.com,REJECT
DOMAIN-SUFFIX,stun.cloudflare.com,REJECT
DOMAIN-SUFFIX,global.stun.twilio.com,REJECT
DOMAIN-SUFFIX,stun.voip.blackberry.com,REJECT
DOMAIN-SUFFIX,stun.sipgate.net,REJECT
DOMAIN-SUFFIX,stun.ekiga.net,REJECT
DOMAIN-SUFFIX,stun.ideasip.com,REJECT

# ==========================================
# Apple 中国区直连白名单 —— 必须前置于所有 Apple RULE-SET
# 上游 iCloud.list 同样包含 icloud.com.cn / icloud-content.com.cn 等域名，
# 且动作为 PROXY；若不前置，国内节点会被规则集抢占并绕行海外出口。
# ==========================================
DOMAIN-SUFFIX,apple.com.cn,DIRECT
DOMAIN-SUFFIX,icloud.com.cn,DIRECT
DOMAIN-SUFFIX,icloud-content.com.cn,DIRECT
DOMAIN-SUFFIX,icloud.net.cn,DIRECT
DOMAIN-SUFFIX,icloud.cn,DIRECT
DOMAIN-SUFFIX,appleicloud.cn,DIRECT
DOMAIN-SUFFIX,apple-icloud.cn,DIRECT
DOMAIN-SUFFIX,icloudapple.cn,DIRECT
DOMAIN-SUFFIX,icloud-apple.cn,DIRECT
DOMAIN-SUFFIX,gs-loc-cn.apple.com,DIRECT
DOMAIN,captive.apple.com,DIRECT

# ==========================================
# Apple Siri / 语音助手直连 —— 必须前置于 AppleProxy RULE-SET
# 上游 AppleProxy.list 含 api-glb-sea.smoot.apple.com、gspe1-ssl.ls.apple.com（PROXY），
# 若后置会被规则集抢占。
# ==========================================
DOMAIN-SUFFIX,guzzoni.apple.com,DIRECT
DOMAIN-SUFFIX,smoot.apple.com,DIRECT
DOMAIN-SUFFIX,siri.apple.com,DIRECT

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
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/OneDrive/OneDrive.list,PROXY
RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Shadowrocket/Binance/Binance.list,DIRECT

# 疑似Binance域名走直连
DOMAIN-SUFFIX,binancezh.cc,DIRECT
DOMAIN-SUFFIX,www.binance.top,DIRECT
DOMAIN-SUFFIX,binance.org,DIRECT
DOMAIN-SUFFIX,binancezh.biz,DIRECT
DOMAIN-SUFFIX,binance-cn.com,DIRECT
DOMAIN-SUFFIX,binance.com,DIRECT
DOMAIN-SUFFIX,binancezh.io,DIRECT
DOMAIN-SUFFIX,binancezh.jp,DIRECT
# 疑似Binance美国域名走代理
DOMAIN-SUFFIX,binance.us,PROXY

# Bitwarden
DOMAIN-SUFFIX,bitwarden.com,PROXY

# Telegram 媒体 CDN（上游仅有 cdn4/cdn5 精确规则，此处用后缀覆盖 cdn1~cdnN）
DOMAIN-SUFFIX,cdn-telegram.org,PROXY

# e充电 去广告
DOMAIN-SUFFIX,flytechtj.com,REJECT
DOMAIN-SUFFIX,puata.info,REJECT
# e充电 隐私防追踪 & 崩溃日志上报
DOMAIN-SUFFIX,yxyylog.echargenet.com,REJECT
DOMAIN-SUFFIX,adash-evone.echargenet.com,REJECT
DOMAIN,pro.bugly.qq.com,REJECT

# Apple Push / APNs —— 全部直连，避免代理长连接抖动导致推送/来电延迟
DOMAIN-SUFFIX,push.apple.com,DIRECT
DOMAIN-SUFFIX,gateway.push.apple.com,DIRECT
DOMAIN-SUFFIX,api.push.apple.com,DIRECT
DOMAIN-SUFFIX,sandbox.push.apple.com,DIRECT

# Apple Relay（Private Cloud Compute）—— 保持代理，不做直连
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
    "binancezh.jp",
    "binance.us",
    "gs-loc-cn.apple.com"
]

# 2. 需要在原上游中精准删除的其他规则/链接列表
rules_to_remove = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AppleNews/AppleNews.list"
]

# ==========================================
# 0. 通知发送能力（提前定义，失败场景也能告警）
# ==========================================
def send_pushdeer(title, desp):
    pushkey = os.environ.get("PUSHDEER_KEY")
    if not pushkey:
        print("未配置 PUSHDEER_KEY 环境变量，跳过发送通知。")
        return

    url = "https://api2.pushdeer.com/message/push"
    data = urllib.parse.urlencode({
        'pushkey': pushkey,
        'text': title,
        'desp': desp
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


def format_fetch_duration():
    raw_ms = os.environ.get("UPSTREAM_FETCH_DURATION_MS", "").strip()
    if raw_ms.isdigit():
        return f"{int(raw_ms) / 1000:.2f} 秒"
    return "未上报（本地运行）"


# 上游拉取状态：优先采用 workflow 上报结果，本地运行时以文件是否就绪为准
fetch_status_raw = os.environ.get("UPSTREAM_FETCH_STATUS", "").strip().lower()
if fetch_status_raw in ("success", "ok", "true"):
    upstream_ok = True
elif fetch_status_raw in ("failed", "fail", "false", "error"):
    upstream_ok = False
else:
    upstream_ok = None  # 未知，交由文件状态判定

if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
    missing_reason = "上游文件不存在" if not os.path.exists(file_path) else "上游文件为空（可能下载失败）"
    fail_desp = "\n".join([
        f"**🕒 构建时间**：{BUILD_TIME}（北京时间）",
        "",
        "**📥 一、上游资源拉取**",
        f"- 拉取状态：❌ **失败**",
        f"- 失败原因：{missing_reason}",
        f"- 条目总数：**0 条**",
        f"- 拉取耗时：**{format_fetch_duration()}**",
        f"- 上游来源：{UPSTREAM_URL}",
        "",
        "**🧩 二、规则注入结果**",
        "- 注入成功：**0 条**",
        "- 注入失败：**未执行**",
        "- 说明：上游文件不可用，注入流程已中止。",
        "",
        "**📦 三、构建产物与耗时**",
        f"- 脚本总耗时：**{time.perf_counter() - START_TIME:.2f} 秒**",
        "- 输出文件：未生成",
        f"- 脚本版本：v{VERSION}",
    ])
    print(f"{missing_reason}: {file_path}")
    send_pushdeer(f"❌ Shadowrocket 规则同步失败 (v{VERSION}) · {BUILD_TIME}", fail_desp)
    sys.exit(1)

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 上游拉取状态兜底：文件可读即视为拉取成功
if upstream_ok is None:
    upstream_ok = True

# 上游原始条目数（规则行）
upstream_rule_count = sum(1 for line in content.split('\n') if rule_line.match(line.strip()))

# ==========================================
# 1. 过滤掉旧的规则（Binance 和 AppleNews）
# ==========================================
lines = content.split('\n')
filtered_lines = []
removed_upstream_count = 0
for line in lines:
    if not line.strip().startswith('#'):
        # 检查是否命中要删除的 Binance 域名
        if any(f",{domain}," in line for domain in domains_to_remove):
            removed_upstream_count += 1
            continue  
            
        # 检查是否命中要删除的具体 RULE-SET 链接
        if any(rule in line for rule in rules_to_remove):
            removed_upstream_count += 1
            continue  
            
    filtered_lines.append(line)

content = '\n'.join(filtered_lines)

# ==========================================
# 2. 插入自定义规则块
# ==========================================
anchor = r'(\[Rule\]\s*#\s*# 黑名单中包含了 GFWList 中定义的无法访问的网站，剩下的网站直连。\s*# 未包含广告过滤\s*#)'

anchor_matched = bool(re.search(anchor, content))
if anchor_matched:
    content = re.sub(anchor, r'\1\n' + custom_rules.strip() + '\n', content, count=1)
else:
    # 兜底防错
    content = content.replace('[Rule]', '[Rule]\n' + custom_rules.strip() + '\n', 1)

# 校验自定义规则注入结果（按单条规则逐一核对是否存在）
injected_rule_lines = [
    line.strip() for line in custom_rules.strip().split('\n')
    if line.strip() and not line.strip().startswith('#')
]
content_line_set = {line.strip() for line in content.split('\n')}
inject_failed = [line for line in injected_rule_lines if line not in content_line_set]
inject_ok = len(injected_rule_lines) - len(inject_failed)

# ==========================================
# 2.5 统一策略动作大小写
# ==========================================
# [ \t]* 只匹配空格和制表符，不匹配换行符。
# (?=\r|\n|$|#) 是前瞻断言，只判断后面是不是换行或注释，但不去替换它们。
content = re.sub(r',[ \t]*Proxy[ \t]*(?=\r|\n|$|#)', r',PROXY', content, flags=re.IGNORECASE)
content = re.sub(r',[ \t]*direct[ \t]*(?=\r|\n|$|#)', r',DIRECT', content, flags=re.IGNORECASE)

# ==========================================
# 2.6 去除完全重复的规则行（保留首次出现的位置与策略）
# ==========================================
# 只处理形如 "TYPE,内容,策略" 的规则行，不触碰 [Section] 段头与 hostname 等配置行。
pre_dedup_rule_count = sum(1 for line in content.split('\n') if rule_line.match(line.strip()))
seen_rules = set()
deduped_lines = []
removed_duplicates = 0
for line in content.split('\n'):
    key = line.strip()
    if rule_line.match(key):
        if key in seen_rules:
            removed_duplicates += 1
            continue
        seen_rules.add(key)
    deduped_lines.append(line)
content = '\n'.join(deduped_lines)
post_dedup_rule_count = len(seen_rules)

# ==========================================
# 3. 追加 MITM hostname
# ==========================================
content = re.sub(
    r'(hostname\s*=\s*.*?\*\.googlevideo\.com)', 
    r'\1,*.ddgksf2013.top,hub.kelee.one',
    content, 
    flags=re.IGNORECASE
)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"版本 {VERSION}: 规则修改、注入、大小写规范化及去重(已删除 {removed_duplicates} 条重复规则)成功！")

# ==========================================
# 4. 汇总构建结果并发送 PushDeer 通知
# ==========================================
total_seconds = time.perf_counter() - START_TIME
abs_file_path = os.path.abspath(file_path)
file_size = os.path.getsize(file_path)
overall_ok = bool(upstream_ok) and not inject_failed

upstream_status_text = "✅ 成功" if upstream_ok else "❌ 失败"
anchor_text = "✅ 精确命中" if anchor_matched else "⚠️ 未命中，已使用兜底插入"
if inject_failed:
    fail_detail_line = "- 失败明细：\n" + "\n".join(f"  - {item}" for item in inject_failed)
else:
    fail_detail_line = "- 失败明细：无"

desp = "\n".join([
    f"**🕒 构建时间**：{BUILD_TIME}（北京时间）",
    "",
    "**📥 一、上游资源拉取**",
    f"- 拉取状态：{upstream_status_text}",
    f"- 条目总数：**{upstream_rule_count:,} 条**",
    f"- 拉取耗时：**{format_fetch_duration()}**",
    f"- 上游来源：{UPSTREAM_URL}",
    "",
    "**🧩 二、规则注入结果**",
    f"- 注入成功：**{inject_ok} 条**",
    f"- 注入失败：**{len(inject_failed)} 条**",
    fail_detail_line,
    f"- 注入锚点：{anchor_text}",
    f"- 上游精准剔除：**{removed_upstream_count} 条**",
    "",
    "**🧹 三、数据去重统计**",
    f"- 原始条目：**{pre_dedup_rule_count:,} 条**",
    f"- 去重后条目：**{post_dedup_rule_count:,} 条**",
    f"- 过滤重复条目：**{removed_duplicates:,} 条**",
    "",
    "**📦 四、构建产物与耗时**",
    f"- 脚本总耗时：**{total_seconds:.2f} 秒**",
    f"- 输出文件：{abs_file_path}",
    f"- 文件大小：**{file_size:,} 字节**",
    f"- 脚本版本：v{VERSION}",
])

title_prefix = "✅ Shadowrocket 规则同步成功" if overall_ok else "⚠️ Shadowrocket 规则同步存在异常"
send_pushdeer(f"{title_prefix} (v{VERSION}) · {BUILD_TIME}", desp)