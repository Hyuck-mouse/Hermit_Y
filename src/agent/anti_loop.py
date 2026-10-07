import logging
from typing import List, Dict, Any
import hashlib
from collections import Counter, deque
import re

logger = logging.getLogger(__name__)


class AntiLoopDetector:
    """循环检测器：检测Agent是否陷入重复操作或策略锁定"""

    # 高价值线索关键词（发现时应立即跟进）
    HIGH_VALUE_CLUES = [
        r'yaml.*import', r'YAML.*deserializ', r'!!python',
        r'pickle.*import', r'base64.*decode.*pickle',
        r'eval\s*\(', r'exec\s*\(', r'subprocess',
        r'system\s*\(', r'popen\s*\(', r'os\.exec',
        r'deserializ', r'unserialize', r'__wakeup',
        r'__destruct', r'__toString', r'POP链',
        r'/api/admin', r'/api/import', r'/api/preview',
        r'admin/yaml', r'admin/import', r'admin/preview',
        r'SSTI', r'ssti.*jinja', r'jinja2.*inject',
        r'werkzeug.*debug', r'debugger.*pin',
        r'file.*upload', r'webshell', r'shell\.php',
        r'Log4j', r'log4j.*jndi',
        r'disable_functions', r'safe_mode',
        r'\bflag\b.*\bformat\b', r'format.*string.*vuln',
        r'overflow', r'buffer.*overflow',
        r'ret2libc', r'return-to-libc',
        r'ROP', r'rop.*chain',
        r'shellcode', r'shell.*spawning',
    ]

    # 策略/方向关键词组（用于检测策略锁定）
    STRATEGY_KEYWORDS = {
        'credential_acquisition': [
            r'register', r'注册', r'signup', r'create.*account',
            r'default.*password', r'默认密码', r'test.*account',
            r'admin.*password', r'admin.*admin', r'admin.*123',
            r'brute.*force', r'密码爆破', r'password.*fuzz',
            r'credential.*search', r'硬编码', r'hardcod.*',
            r'\.env.*file', r'config.*file', r'password.*file',
            r'api/auth', r'auth/login', r'auth/register',
            r'signup', r'createUser', r'create_user',
            r'账号', r'凭据', r'credential',
        ],
        'authentication_bypass': [
            r'X-Archive-Mobile', r'auth.*bypass', r'认证绕过',
            r'header.*bypass', r'request.*header.*forge',
            r'session.*forge', r'cookie.*forge',
            r'admin.*header', r'role.*bypass',
            r'path.*bypass', r'路径绕过', r'path.*param',
            r'Ward.*gateway', r'ward.*policy', r'canonical.*path',
            r'\.htaccess', r'\.user\.ini',
            r'bypass.*auth', r'bypass.*login',
        ],
        'information_disclosure': [
            r'source.*map', r'\.map.*file', r'sourcemap',
            r'js.*analysis', r'javascript.*analys',
            r'credential.*search', r'硬编码.*密',
            r'backup.*file', r'\.bak', r'\.swp', r'\.git',
        ],
        'directory_exploration': [
            r'dir.*brute', r'directory.*scan', r'dirb',
            r'gobuster', r'ffuf', r'dirsearch',
            r'common.*path', r'路径扫描',
        ],
    }

    def __init__(self):
        self.tool_call_history: deque = deque(maxlen=30)
        self.previous_tool_signatures = []
        self.direction_history: deque = deque(maxlen=50)
        self.clue_discovery_count = 0
        self.last_high_value_clue = None

    def detect_loop(self, history: List[Dict[str, Any]]) -> bool:
        if len(history) < 10:
            return False

        recent_tool_calls = []
        for entry in history[-25:]:
            content = entry.get("content", "")
            if isinstance(content, str) and "工具执行结果" in content:
                for line in content.split("\n"):
                    if "(" in line and "):" in line:
                        tool_sig = line.split("):")[0]
                        recent_tool_calls.append(tool_sig)

        # 检测1: 相同工具调用重复15次以上
        if len(recent_tool_calls) >= 15:
            counter = Counter(recent_tool_calls)
            for sig, count in counter.items():
                if count >= 15:
                    logger.warning(f"检测1触发：工具调用 {sig} 重复 {count} 次")
                    return True

        # 检测2: 策略锁定 - 连续N次都在同一方向但没有新进展
        if self._detect_strategy_lock(history):
            logger.warning("检测2触发：策略锁定 - 长时间在同一方向无进展")
            return True

        # 检测3: 高价值线索发现后未跟进
        if self._detect_clue_ignored(history):
            logger.warning("检测3触发：发现高价值线索但未跟进")
            return True

        return False

    def check_auth_and_credentials(self, history: List[Dict[str, Any]]) -> str:
        """主动检查：是否遇到了需要认证的端点但还没尝试获取凭据？
        返回空字符串表示无需提醒，返回提醒消息表示需要提醒AI"""
        if len(history) < 5:
            return ""

        all_content = self._get_all_content(history)

        # 检查是否遇到了需要认证的响应
        auth_required = bool(re.search(
            r'401|403|Authentication required|Unauthorized|需要认证|需要登录',
            all_content, re.IGNORECASE
        ))

        if not auth_required:
            return ""

        # 检查是否已经尝试过注册
        tried_register = bool(re.search(
            r'register|signup|create.*account|注册|sign.?up',
            all_content, re.IGNORECASE
        ))

        # 检查是否已经尝试过默认凭据登录
        tried_default = bool(re.search(
            r'admin.*password|admin.*admin123|test.*test123|默认密码|admin@.*login',
            all_content, re.IGNORECASE
        ))

        # 检查是否已经在做认证绕过
        doing_bypass = bool(re.search(
            r'X-Archive-Mobile|auth.*bypass|认证绕过|header.*bypass|path.*bypass',
            all_content, re.IGNORECASE
        ))

        # 检查是否已经提取了用户名（如 E. Vale → evale）
        found_usernames = bool(re.search(
            r'[A-Z]\.\s+[A-Z][a-z]+.*[A-Z]\.\s+[A-Z][a-z]+|[a-z]+\.[a-z]+@blackarchive|evale|jrenn|icross',
            all_content, re.IGNORECASE
        ))

        # 检查是否下载了 mobile-archive.js.map
        checked_mobile_map = bool(re.search(
            r'mobile-archive\.js\.map|mobile.*archive.*map|legacy.*session',
            all_content, re.IGNORECASE
        ))

        # 检查是否在用用户名+移动头组合测试
        tried_mobile_bypass = bool(re.search(
            r'BA-iOS.*2\.6|mobile.*bypass|X-Archive-Mobile.*admin|mobile.*header.*login',
            all_content, re.IGNORECASE
        ))

        # 场景1：发现了用户名和X-Archive-Mobile线索，但在做密码爆破
        if found_usernames and doing_bypass and not tried_mobile_bypass:
            logger.warning("主动检测：发现了用户名和移动头机制，但未尝试组合利用")
            return (
                "**SCENARIO_1** ⚠️ 重大机会！你发现了用户名和 X-Archive-Mobile 头机制，但还没有将它们组合利用！\n"
                "立即执行以下攻击链：\n"
                "1. 从Notes/源码提取人名 → 转为邮箱格式（去掉点号）：\n"
                "   'E. Vale' → evale@blackarchive.local\n"
                "   'J. Renn' → jrenn@blackarchive.local\n"
                "   'I. Cross' → icross@blackarchive.local\n"
                "2. 下载 mobile-archive.js.map 分析 legacy/session.ts 的完整逻辑\n"
                "3. 用 X-Archive-Mobile: BA-iOS/2.6.1 头 + 已知用户名 + 短密码测试登录\n"
                "4. 核心原理：移动客户端兼容模式可能跳过密码校验\n"
                "5. 成功获取Cookie后，立即访问 /api/admin/yaml/import 利用反序列化！"
            )

        # 场景2：知道X-Archive-Mobile但还没下载mobile-archive.js.map
        if doing_bypass and not checked_mobile_map:
            logger.warning("主动检测：知道X-Archive-Mobile机制但未下载mobile-archive.js.map")
            return (
                "**SCENARIO_2** ⚠️ 你发现了 X-Archive-Mobile 头机制，但还没有深入分析 mobile-archive.js.map！\n"
                "立即下载并分析：\n"
                "1. GET /mobile-archive.js.map → 下载source map\n"
                "2. 提取 legacy/session.ts 中的认证合并逻辑\n"
                "3. 确认 admin:true 字段的传递方式\n"
                "4. 理解完整的绕过流程后再尝试"
            )

        # 场景3：遇到认证保护但还没尝试注册和默认凭据，直接尝试绕过
        if not tried_register and not tried_default and doing_bypass:
            logger.warning("主动检测：遇到认证保护但跳过了注册/默认凭据，直接尝试绕过")
            return (
                "**SCENARIO_3** ⚠️ 提醒：你遇到了需要认证的端点，但还没有尝试【注册】或【默认凭据登录】！\n"
                "请立即按以下顺序尝试：\n"
                "1. POST /api/auth/register 或 /api/register 或 /signup 尝试注册账号\n"
                "2. POST /api/auth/login 尝试默认凭据：admin/admin123, admin/password1, test/test123\n"
                "3. 在JS/sourcemap中搜索 email, password, admin, test 等关键词找硬编码凭据\n"
                "只有以上全部失败后，才尝试认证绕过！"
            )

        return ""

    def get_strategy_suggestion(self, history: List[Dict[str, Any]]) -> str:
        """获取策略转向建议"""
        suggestions = []

        # 检查是否有高价值线索被发现但未跟进
        all_content = self._get_all_content(history)
        found_clues = []
        for pattern in self.HIGH_VALUE_CLUES:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            if matches:
                found_clues.append((pattern, matches[0][:50]))

        if found_clues:
            clue_names = [p.replace('\\b', '').replace('.*', '').replace(r'\b', '') for p, _ in found_clues[:3]]
            suggestions.append(f"发现高价值线索: {', '.join(clue_names)}。优先跟进这些线索！")

        # 检查当前策略方向
        current_direction = self._get_current_direction(history)
        if current_direction:
            suggestions.append(f"当前策略方向: {current_direction}。")

        # 检查是否有用户名线索
        has_usernames = bool(re.search(
            r'[A-Z]\.\s+[A-Z][a-z]+.*[A-Z]\.\s+[A-Z][a-z]+|evale|jrenn|icross',
            all_content, re.IGNORECASE
        ))
        has_mobile_map = bool(re.search(
            r'mobile-archive\.js\.map|legacy.*session',
            all_content, re.IGNORECASE
        ))
        has_mobile_bypass_attempt = bool(re.search(
            r'BA-iOS|mobile.*bypass',
            all_content, re.IGNORECASE
        ))

        # 针对认证锁定的特殊建议
        if current_direction == 'authentication_bypass':
            if has_usernames and not has_mobile_bypass_attempt:
                suggestions.append(
                    "⚠️ 你已经找到了用户名（E.Vale→evale, J.Renn→jrenn, I.Cross→icross），"
                    "但没有用它们配合 X-Archive-Mobile 头测试！\n"
                    "这是最高优先级！立即：\n"
                    "1. 下载 mobile-archive.js.map\n"
                    "2. 用已知用户名 + X-Archive-Mobile: BA-iOS/2.6.1 + 短密码 测试\n"
                    "3. 核心：移动客户端可能绕过密码校验"
                )
            elif has_usernames and has_mobile_map and not has_mobile_bypass_attempt:
                suggestions.append(
                    "⚠️ 你有了用户名和 mobile-archive.js.map，现在必须测试组合利用！\n"
                    "用 evale@blackarchive.local + X-Archive-Mobile: BA-iOS/2.6.1 + 任意8位密码 测试"
                )
            else:
                suggestions.append(
                    "⚠️ 检测到你在认证绕路上已经投入太多迭代！\n"
                    "立即转向以下路径（按优先级排序）：\n"
                    "1. 【注册接口】POST /api/auth/register 或 /api/register 尝试注册账号\n"
                    "2. 【默认凭据】尝试 admin/admin123, admin/password1, test/test123\n"
                    "3. 【提取用户名】从JS源码/Notes中提取人名（如E.Vale→evale），拼成邮箱\n"
                    "4. 【移动头绕过】如果知道X-Archive-Mobile，用已知用户名+头+短密码测试\n"
                    "5. 【以上全部失败后】才考虑路径绕过、session伪造等复杂方法\n"
                    "记住：先拿到账号，再搞漏洞！"
                )
        elif current_direction == 'credential_acquisition':
            suggestions.append(
                "你正在尝试获取凭据。如果注册和默认凭据都失败了：\n"
                "1. 检查JS源码中的硬编码凭据、测试账号、API密钥\n"
                "2. 从Notes/源码中提取人名作为用户名（E.Vale→evale, J.Renn→jrenn）\n"
                "3. 检查robots.txt, sitemap.xml等公开文件\n"
                "4. 如果以上都失败，可以尝试X-Archive-Mobile头绕过"
            )

        # 建议转向
        other_directions = [k for k in self.STRATEGY_KEYWORDS.keys() if k != current_direction]
        if other_directions and current_direction not in ('authentication_bypass', 'credential_acquisition'):
            suggestions.append(f"建议转向其他方向: {', '.join(other_directions)}")

        return "\n".join(suggestions) if suggestions else ""

    def _get_all_content(self, history: List[Dict[str, Any]]) -> str:
        """获取所有历史内容的组合"""
        all_content = ""
        for entry in history[-30:]:
            content = entry.get("content", "")
            if isinstance(content, str):
                all_content += content + "\n"
        return all_content

    def _detect_strategy_lock(self, history: List[Dict[str, Any]]) -> bool:
        """检测策略锁定：连续N次都在同一方向但没有新进展"""
        if len(history) < 15:
            return False

        # 分析最近12次迭代的思考内容
        recent_thoughts = []
        for entry in history[-12:]:
            content = entry.get("content", "")
            if isinstance(content, str) and "[AI] [思考]" in content:
                recent_thoughts.append(content)

        if len(recent_thoughts) < 6:
            return False

        # 统计每个策略方向的出现次数
        direction_counts = Counter()
        for thought in recent_thoughts:
            for direction, keywords in self.STRATEGY_KEYWORDS.items():
                for keyword in keywords:
                    if re.search(keyword, thought, re.IGNORECASE):
                        direction_counts[direction] += 1
                        break

        if not direction_counts:
            return False

        most_common_dir, count = direction_counts.most_common(1)[0]
        
        # 认证绕过：更敏感，6次即可触发
        # 其他方向：8次触发
        threshold = 6 if most_common_dir == 'authentication_bypass' else 8
        
        if count >= threshold:
            # 检查最近的输出是否有新进展
            latest_outputs = []
            for entry in history[-5:]:
                content = entry.get("content", "")
                if isinstance(content, str) and "工具执行结果" in content:
                    latest_outputs.append(content)

            failed_count = sum(
                1 for output in latest_outputs[:3]
                if any(kw in output.lower() for kw in ["error", "失败", "required", "401", "403", "unauthorized", "无效", "invalid"])
                or len(output) < 100
            )
            if failed_count >= 2:
                logger.warning(f"策略锁定检测: 方向={most_common_dir}, 出现次数={count}, 最近失败次数={failed_count}")
                return True

        return False

    def _detect_clue_ignored(self, history: List[Dict[str, Any]]) -> bool:
        """检测高价值线索是否被忽略"""
        if len(history) < 15:
            return False

        all_content = self._get_all_content(history)

        # 检查是否发现了高价值线索
        found_clues = []
        for pattern in self.HIGH_VALUE_CLUES:
            matches = re.findall(pattern, all_content, re.IGNORECASE)
            if matches:
                found_clues.append(pattern)

        if not found_clues:
            return False

        # 如果新发现了线索，更新记录
        clue_key = found_clues[0][:30]  # 简化的线索标识
        if self.last_high_value_clue != clue_key:
            self.last_high_value_clue = clue_key
            self.clue_discovery_count += 1
            logger.info(f"发现高价值线索: {clue_key}")

        # 检查发现线索后是否在跟进
        # 取发现线索前后的迭代进行比较
        recent_entries = history[-10:]
        recent_thoughts = []
        for entry in recent_entries:
            content = entry.get("content", "")
            if isinstance(content, str) and "[AI] [思考]" in content:
                recent_thoughts.append(content)

        # 检查最近的思考是否提到了发现的线索
        for thought in recent_thoughts:
            for pattern in found_clues[:3]:
                if re.search(pattern, thought, re.IGNORECASE):
                    # AI提到了线索，检查是否在尝试利用
                    if any(action in thought.lower() for action in ['尝试', '测试', '利用', '构造', '发送', '利用', 'exploit', 'attack', 'use', 'test']):
                        return False  # AI正在跟进线索

        # 如果发现线索后5次迭代仍未跟进，视为线索被忽略
        if len(recent_entries) >= 5:
            # 检查最近的输出是否与线索相关
            clue_patterns_text = [p.replace('\\b', '').replace('.*', '') for p in found_clues[:3]]
            for entry in recent_entries[-3:]:
                content = entry.get("content", "")
                if isinstance(content, str):
                    for pattern in clue_patterns_text:
                        if pattern.lower() in content.lower():
                            return False  # 线索被跟进

            logger.warning(f"高价值线索被忽略: {found_clues[:3]}")
            return True

        return False

    def _get_current_direction(self, history: List[Dict[str, Any]]) -> str:
        """获取当前主要策略方向"""
        recent_thoughts = []
        for entry in history[-10:]:
            content = entry.get("content", "")
            if isinstance(content, str) and "[AI] [思考]" in content:
                recent_thoughts.append(content)

        direction_counts = Counter()
        for thought in recent_thoughts:
            for direction, keywords in self.STRATEGY_KEYWORDS.items():
                for keyword in keywords:
                    if re.search(keyword, thought, re.IGNORECASE):
                        direction_counts[direction] += 1
                        break

        if direction_counts:
            return direction_counts.most_common(1)[0][0]
        return None