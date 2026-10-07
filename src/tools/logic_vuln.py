"""
逻辑漏洞检测工具模块
提供会话保持HTTP、越权检测、参数Fuzz、竞争条件、流程绕过等逻辑漏洞检测能力
"""
import asyncio
import aiohttp
import json
import copy
import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# ==================== 会话管理器 ====================

_session_manager: Optional["SessionManager"] = None


class SessionManager:
    """管理多个持久化HTTP会话，跨工具调用保持Cookie/Token"""

    def __init__(self):
        self._sessions: Dict[str, aiohttp.ClientSession] = {}

    def get_session(self, session_id: str) -> aiohttp.ClientSession:
        if session_id not in self._sessions:
            jar = aiohttp.CookieJar(unsafe=True)
            timeout = aiohttp.ClientTimeout(total=30)
            self._sessions[session_id] = aiohttp.ClientSession(
                cookie_jar=jar, timeout=timeout
            )
        return self._sessions[session_id]

    async def close_session(self, session_id: str):
        if session_id in self._sessions:
            await self._sessions[session_id].close()
            del self._sessions[session_id]

    async def close_all(self):
        for sid in list(self._sessions.keys()):
            await self.close_session(sid)


def _get_session_manager() -> SessionManager:
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


# ==================== 工具函数 ====================

async def logic_session_http(
    session_id: str,
    method: str,
    url: str,
    headers: str = "",
    data: str = "",
    json_data: str = "",
) -> Dict[str, Any]:
    """会话保持的HTTP请求（跨调用维持Cookie/Token）。
    session_id: 会话标识(自定义字符串如'user1'/'admin')，相同ID共享Cookie
    method: HTTP方法(GET/POST/PUT/DELETE)
    url: 请求URL
    headers: 额外请求头(JSON字符串,如{"Authorization":"Bearer xxx"})
    data: POST表单数据(JSON字符串)
    json_data: POST JSON数据(JSON字符串,与data二选一)"""
    sm = _get_session_manager()
    session = sm.get_session(session_id)

    req_headers: Optional[Dict] = None
    if headers:
        try:
            req_headers = json.loads(headers)
        except json.JSONDecodeError:
            return {"success": False, "error": f"headers不是有效JSON: {headers}"}

    kwargs: Dict[str, Any] = {}
    if req_headers:
        kwargs["headers"] = req_headers
    if json_data:
        try:
            kwargs["json"] = json.loads(json_data)
        except json.JSONDecodeError:
            return {"success": False, "error": f"json_data不是有效JSON: {json_data}"}
    elif data:
        try:
            kwargs["data"] = json.loads(data)
        except json.JSONDecodeError:
            return {"success": False, "error": f"data不是有效JSON: {data}"}

    try:
        async with session.request(method.upper(), url, **kwargs) as resp:
            try:
                content = await resp.json()
                content_type = "json"
            except Exception:
                try:
                    content = await resp.text()
                    content_type = "text"
                except Exception:
                    raw = await resp.read()
                    content = f"<binary {len(raw)} bytes>"
                    content_type = "binary"

            # 收集当前会话的 cookies
            cookies = {}
            for cookie in session.cookie_jar:
                cookies[cookie.key] = cookie.value

            return {
                "success": True,
                "session_id": session_id,
                "status": resp.status,
                "headers": dict(resp.headers),
                "content": content,
                "content_type": content_type,
                "url": str(resp.url),
                "cookies": cookies,
            }
    except asyncio.TimeoutError:
        return {"success": False, "error": "请求超时(30s)"}
    except aiohttp.ClientError as e:
        return {"success": False, "error": f"HTTP请求失败: {str(e) or type(e).__name__}"}
    except Exception as e:
        return {"success": False, "error": f"异常: {str(e)}"}


async def logic_idor_test(
    url: str,
    param_name: str,
    current_value: str,
    method: str = "GET",
    test_range: str = "",
    headers: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """越权检测(IDOR/水平越权/垂直越权)。通过遍历/递增ID参数检测是否可访问其他用户数据。
    url: 目标URL(含占位符__VALUE__替换param值,如http://target/api/user?id=__VALUE__)
    param_name: 参数名(如user_id/order_id)
    current_value: 当前用户的值(作为基准)
    method: GET或POST
    test_range: 自定义测试值列表(逗号分隔如1,2,3,admin,0,-1)。留空则自动生成
    headers: 额外请求头(JSON)
    session_id: 会话ID(需先logic_session_http登录获取session)"""
    # 构建测试值列表
    if test_range:
        test_values = [v.strip() for v in test_range.split(",")]
    else:
        # 自动生成测试值
        test_values = []
        try:
            base = int(current_value)
            # 前后各5个 + 边界值
            for i in range(max(0, base - 5), base + 6):
                if i != base:
                    test_values.append(str(i))
            test_values.extend(["0", "-1", "1", "999999", "admin", "root"])
        except ValueError:
            # 非数字，尝试其他常见值
            test_values = ["admin", "root", "test", "guest", "user", "1", "0"]

    # 移除当前值
    test_values = [v for v in test_values if v != current_value]

    req_headers: Optional[Dict] = None
    if headers:
        try:
            req_headers = json.loads(headers)
        except json.JSONDecodeError:
            req_headers = None

    sm = _get_session_manager()

    async def _fetch(val: str) -> Dict[str, Any]:
        # 替换URL中的占位符
        target_url = url.replace("__VALUE__", val)
        if "__VALUE__" not in url:
            # 没有占位符，追加参数
            sep = "&" if "?" in target_url else "?"
            target_url = f"{target_url}{sep}{param_name}={val}"

        if session_id:
            session = sm.get_session(session_id)
        else:
            jar = aiohttp.CookieJar(unsafe=True)
            session = aiohttp.ClientSession(
                cookie_jar=jar, timeout=aiohttp.ClientTimeout(total=10)
            )

        kwargs: Dict[str, Any] = {}
        if req_headers:
            kwargs["headers"] = req_headers

        try:
            async with session.request(method.upper(), target_url, **kwargs) as resp:
                try:
                    content = await resp.json()
                except Exception:
                    content = await resp.text()
                content_str = json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)
                return {
                    "value": val,
                    "status": resp.status,
                    "content": content_str[:500],
                    "content_length": len(content_str),
                }
        except Exception as e:
            return {"value": val, "error": str(e)}
        finally:
            if not session_id:
                await session.close()

    # 获取基准响应
    baseline = await _fetch(current_value)
    if "error" in baseline:
        return {"success": False, "error": f"基准请求失败: {baseline['error']}"}

    baseline_len = baseline.get("content_length", 0)
    baseline_status = baseline.get("status", 0)

    # 并发测试所有值
    tasks = [_fetch(v) for v in test_values]
    results = await asyncio.gather(*tasks)

    # 分析结果：寻找异常响应
    findings: List[Dict] = []
    for r in results:
        if "error" in r:
            continue
        r_status = r.get("status", 0)
        r_len = r.get("content_length", 0)

        # 检测指标：
        # 1. 状态码不同于基准但不是403/401(那些是正常拒绝)
        # 2. 响应长度与基准不同且不是错误页面
        # 3. 200状态但内容不同(可能返回了其他用户数据)
        is_accessible = r_status == 200
        is_different_from_baseline = r_status != baseline_status or abs(r_len - baseline_len) > 50
        is_not_denied = r_status not in (401, 403)

        if is_accessible and is_different_from_baseline and is_not_denied:
            findings.append({
                "test_value": r["value"],
                "status": r_status,
                "content_length": r_len,
                "baseline_status": baseline_status,
                "baseline_length": baseline_len,
                "content_preview": r.get("content", "")[:200],
                "risk": "可能存在越权访问" if r["value"] != current_value else "",
            })

    return {
        "success": True,
        "url": url,
        "param_name": param_name,
        "current_value": current_value,
        "baseline": baseline,
        "total_tested": len(test_values),
        "findings_count": len(findings),
        "findings": findings,
        "all_results": results,
        "summary": f"测试了{len(test_values)}个值，发现{len(findings)}个潜在越权" if findings else f"测试了{len(test_values)}个值，未发现明显越权",
    }


async def logic_param_fuzz(
    url: str,
    method: str = "GET",
    param_name: str = "",
    param_value: str = "",
    extra_params: str = "",
    headers: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """参数边界值Fuzz测试。测试负数/零/超大值/空值/类型混淆等边界情况。
    url: 目标URL
    method: GET或POST
    param_name: 要Fuzz的参数名
    param_value: 原始参数值(用于基准对比)
    extra_params: 其他固定参数(JSON字符串如{"username":"test"})
    headers: 额外请求头(JSON)
    session_id: 会话ID"""
    if not param_name:
        return {"success": False, "error": "必须提供param_name"}

    # 边界值测试集
    fuzz_values: List[Dict[str, Any]] = [
        {"value": "0", "desc": "零值"},
        {"value": "-1", "desc": "负数"},
        {"value": "-99999", "desc": "大负数"},
        {"value": "999999999", "desc": "超大值"},
        {"value": "", "desc": "空值"},
        {"value": "null", "desc": "null字符串"},
        {"value": "None", "desc": "None字符串"},
        {"value": "true", "desc": "布尔true"},
        {"value": "false", "desc": "布尔false"},
        {"value": "[]", "desc": "空数组"},
        {"value": "{}", "desc": "空对象"},
        {"value": "' or '1'='1", "desc": "SQL注入探测"},
        {"value": "{{7*7}}", "desc": "SSTI探测"},
        {"value": "../../../etc/passwd", "desc": "路径穿越探测"},
        {"value": "<script>alert(1)</script>", "desc": "XSS探测"},
    ]

    # 如果原始值是数字，添加特殊数字
    try:
        int(param_value)
        fuzz_values.insert(0, {"value": param_value, "desc": "原始值(基准)"})
        fuzz_values.extend([
            {"value": "0x10", "desc": "十六进制"},
            {"value": "1e10", "desc": "科学计数法"},
            {"value": "0b1", "desc": "二进制"},
            {"value": "+0", "desc": "正零"},
            {"value": "00", "desc": "前导零"},
        ])
    except ValueError:
        fuzz_values.insert(0, {"value": param_value, "desc": "原始值(基准)"})

    # 解析额外参数
    fixed_params: Dict = {}
    if extra_params:
        try:
            fixed_params = json.loads(extra_params)
        except json.JSONDecodeError:
            pass

    req_headers: Optional[Dict] = None
    if headers:
        try:
            req_headers = json.loads(headers)
        except json.JSONDecodeError:
            pass

    sm = _get_session_manager()

    async def _fetch(val: str) -> Dict[str, Any]:
        params = {**fixed_params, param_name: val}

        if session_id:
            session = sm.get_session(session_id)
        else:
            jar = aiohttp.CookieJar(unsafe=True)
            session = aiohttp.ClientSession(
                cookie_jar=jar, timeout=aiohttp.ClientTimeout(total=10)
            )

        kwargs: Dict[str, Any] = {}
        if req_headers:
            kwargs["headers"] = req_headers

        try:
            if method.upper() == "GET":
                kwargs["params"] = params
            else:
                kwargs["data"] = params

            async with session.request(method.upper(), url, **kwargs) as resp:
                try:
                    content = await resp.json()
                except Exception:
                    content = await resp.text()
                content_str = json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)
                return {
                    "value": val,
                    "status": resp.status,
                    "content_length": len(content_str),
                    "content_preview": content_str[:300],
                }
        except Exception as e:
            return {"value": val, "error": str(e)}
        finally:
            if not session_id:
                await session.close()

    # 获取基准响应
    baseline = await _fetch(param_value)
    baseline_status = baseline.get("status", 0)
    baseline_len = baseline.get("content_length", 0)

    # 并发测试
    test_values = [f["value"] for f in fuzz_values[1:]]  # 跳过基准
    tasks = [_fetch(v) for v in test_values]
    results = await asyncio.gather(*tasks)

    # 分析异常响应
    findings: List[Dict] = []
    for fv, r in zip(fuzz_values[1:], results):
        if "error" in r:
            continue
        r_status = r.get("status", 0)
        r_len = r.get("content_length", 0)

        # 异常指标
        anomalies = []
        if r_status != baseline_status:
            anomalies.append(f"状态码变化 {baseline_status}→{r_status}")
        if abs(r_len - baseline_len) > 100:
            anomalies.append(f"响应长度变化 {baseline_len}→{r_len}")
        if r_status == 500:
            anomalies.append("服务器错误(可能触发异常)")
        if r_status == 200 and r_len != baseline_len:
            anomalies.append("200但内容不同(可能逻辑绕过)")

        if anomalies:
            findings.append({
                "fuzz_value": fv["value"],
                "desc": fv["desc"],
                "status": r_status,
                "content_length": r_len,
                "anomalies": anomalies,
                "content_preview": r.get("content_preview", ""),
            })

    return {
        "success": True,
        "url": url,
        "param_name": param_name,
        "baseline_value": param_value,
        "baseline_status": baseline_status,
        "baseline_length": baseline_len,
        "total_tested": len(test_values),
        "findings_count": len(findings),
        "findings": findings,
        "summary": f"Fuzz测试{len(test_values)}个值，发现{len(findings)}个异常响应" if findings else f"Fuzz测试{len(test_values)}个值，未发现异常",
    }


async def logic_race_condition(
    url: str,
    method: str = "POST",
    data: str = "",
    json_data: str = "",
    headers: str = "",
    concurrency: int = 10,
    delay_ms: int = 0,
    session_id: str = "",
) -> Dict[str, Any]:
    """竞争条件测试。并发发送多个相同请求，检测竞态条件(如余额双花、优惠券重复使用)。
    url: 目标URL
    method: HTTP方法
    data: 表单数据(JSON)
    json_data: JSON数据(JSON,与data二选一)
    headers: 额外请求头(JSON)
    concurrency: 并发请求数(默认10)
    delay_ms: 请求间延迟(毫秒,0=同时发送)
    session_id: 会话ID"""
    if concurrency > 50:
        concurrency = 50  # 限制最大并发

    req_headers: Optional[Dict] = None
    if headers:
        try:
            req_headers = json.loads(headers)
        except json.JSONDecodeError:
            pass

    post_data: Optional[Dict] = None
    if json_data:
        try:
            post_data = json.loads(json_data)
            is_json = True
        except json.JSONDecodeError:
            return {"success": False, "error": f"json_data不是有效JSON"}
    elif data:
        try:
            post_data = json.loads(data)
            is_json = False
        except json.JSONDecodeError:
            return {"success": False, "error": f"data不是有效JSON"}
    else:
        is_json = False

    sm = _get_session_manager()

    async def _single_request(idx: int) -> Dict[str, Any]:
        if session_id:
            session = sm.get_session(session_id)
        else:
            jar = aiohttp.CookieJar(unsafe=True)
            session = aiohttp.ClientSession(
                cookie_jar=jar, timeout=aiohttp.ClientTimeout(total=15)
            )

        kwargs: Dict[str, Any] = {}
        if req_headers:
            kwargs["headers"] = req_headers
        if is_json and post_data:
            kwargs["json"] = post_data
        elif post_data:
            kwargs["data"] = post_data

        if delay_ms > 0:
            await asyncio.sleep(delay_ms * idx / 1000.0)

        try:
            async with session.request(method.upper(), url, **kwargs) as resp:
                try:
                    content = await resp.json()
                except Exception:
                    content = await resp.text()
                content_str = json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)
                return {
                    "index": idx,
                    "status": resp.status,
                    "content_length": len(content_str),
                    "content_preview": content_str[:200],
                }
        except Exception as e:
            return {"index": idx, "error": str(e)}
        finally:
            if not session_id:
                await session.close()

    # 同时发送所有请求
    tasks = [_single_request(i) for i in range(concurrency)]
    results = await asyncio.gather(*tasks)

    # 分析结果
    status_codes = [r.get("status") for r in results if "status" in r]
    success_count = sum(1 for s in status_codes if s == 200)
    error_count = sum(1 for r in results if "error" in r)

    # 检测竞争条件迹象
    findings: List[str] = []
    if success_count > 1:
        # 检查响应内容是否相同（如果多个请求都成功，可能存在竞态）
        success_responses = [r for r in results if r.get("status") == 200]
        contents = [r.get("content_preview", "") for r in success_responses]
        unique_contents = set(contents)
        if len(unique_contents) == 1:
            findings.append(f"所有{success_count}个成功响应内容相同（可能操作被重复执行）")
        else:
            findings.append(f"{success_count}个请求成功但响应内容不同（可能存在竞态条件）")

    if error_count > 0:
        findings.append(f"{error_count}个请求失败（可能被速率限制或触发异常）")

    # 检查状态码分布
    status_dist = {}
    for s in status_codes:
        status_dist[s] = status_dist.get(s, 0) + 1

    return {
        "success": True,
        "url": url,
        "method": method,
        "concurrency": concurrency,
        "total_requests": concurrency,
        "success_count": success_count,
        "error_count": error_count,
        "status_distribution": status_dist,
        "findings": findings,
        "all_results": results,
        "summary": f"并发{concurrency}请求: {success_count}成功, {error_count}失败。{'; '.join(findings) if findings else '无明显竞态'}",
    }


async def logic_flow_test(
    steps: str,
    session_id: str = "flow_test",
) -> Dict[str, Any]:
    """业务流程绕过测试。执行一系列API调用，支持跳步/重放/乱序测试。
    steps: 步骤列表JSON字符串,每个步骤含:
      - name: 步骤名称
      - method: HTTP方法
      - url: 请求URL
      - headers: 请求头(JSON字符串,可选)
      - data: 表单数据(JSON字符串,可选)
      - json_data: JSON数据(JSON字符串,可选)
      - extract: 从响应中提取的值(JSONPath风格如"$.token",存入后续步骤变量{{token}})
    session_id: 会话ID,相同ID共享Cookie"""
    try:
        step_list = json.loads(steps)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"steps不是有效JSON: {e}"}

    if not isinstance(step_list, list) or len(step_list) < 2:
        return {"success": False, "error": "steps必须是包含至少2个步骤的JSON数组"}

    sm = _get_session_manager()
    session = sm.get_session(session_id)
    variables: Dict[str, str] = {}  # 提取的变量
    results: List[Dict] = []

    async def _execute_step(step: Dict) -> Dict[str, Any]:
        step_name = step.get("name", "unnamed")
        method = step.get("method", "GET").upper()
        url = step.get("url", "")

        # 变量替换
        for var_name, var_val in variables.items():
            url = url.replace(f"{{{{{var_name}}}}}", var_val)

        headers: Optional[Dict] = None
        hdr_str = step.get("headers", "")
        if hdr_str:
            try:
                headers = json.loads(hdr_str)
            except json.JSONDecodeError:
                pass

        kwargs: Dict[str, Any] = {}
        if headers:
            kwargs["headers"] = headers

        json_str = step.get("json_data", "")
        data_str = step.get("data", "")

        if json_str:
            try:
                jd = json.loads(json_str)
                # 变量替换
                jd_str = json.dumps(jd)
                for var_name, var_val in variables.items():
                    jd_str = jd_str.replace(f"{{{{{var_name}}}}}", var_val)
                kwargs["json"] = json.loads(jd_str)
            except json.JSONDecodeError:
                pass
        elif data_str:
            try:
                dd = json.loads(data_str)
                dd_str = json.dumps(dd)
                for var_name, var_val in variables.items():
                    dd_str = dd_str.replace(f"{{{{{var_name}}}}}", var_val)
                kwargs["data"] = json.loads(dd_str)
            except json.JSONDecodeError:
                pass

        try:
            async with session.request(method, url, **kwargs) as resp:
                try:
                    content = await resp.json()
                except Exception:
                    content = await resp.text()
                content_str = json.dumps(content, ensure_ascii=False) if isinstance(content, (dict, list)) else str(content)

                # 提取变量
                extract = step.get("extract", "")
                if extract:
                    try:
                        extract_rules = json.loads(extract)
                        for var_name, json_path in extract_rules.items():
                            # 简单的JSONPath提取: $.key 或 $.data.key
                            keys = json_path.lstrip("$.").split(".")
                            val = content
                            for k in keys:
                                if isinstance(val, dict):
                                    val = val.get(k, "")
                                else:
                                    val = ""
                                    break
                            variables[var_name] = str(val)
                    except (json.JSONDecodeError, Exception):
                        pass

                return {
                    "name": step_name,
                    "method": method,
                    "url": url,
                    "status": resp.status,
                    "content_length": len(content_str),
                    "content_preview": content_str[:300],
                    "extracted_vars": {k: v for k, v in variables.items()} if extract else {},
                }
        except Exception as e:
            return {"name": step_name, "error": str(e)}

    # 1. 正常执行全部流程（基准）
    for step in step_list:
        result = await _execute_step(step)
        results.append(result)
        if "error" in result:
            return {
                "success": False,
                "error": f"步骤 '{result.get('name')}' 执行失败: {result['error']}",
                "partial_results": results,
            }

    baseline_results = copy.deepcopy(results)
    baseline_success = all(r.get("status", 500) == 200 for r in baseline_results)

    # 2. 跳过中间步骤测试（跳过第i步,执行其余步骤）
    skip_findings: List[Dict] = []
    for skip_idx in range(1, len(step_list) - 1):
        # 重置会话和变量
        await sm.close_session(session_id)
        session = sm.get_session(session_id)
        variables.clear()
        skip_results = []
        skip_success = True

        for i, step in enumerate(step_list):
            if i == skip_idx:
                continue  # 跳过此步骤
            result = await _execute_step(step)
            skip_results.append(result)
            if "error" in result or result.get("status", 500) != 200:
                skip_success = False
                break

        if skip_success and baseline_success:
            # 跳过步骤后仍然成功 → 流程绕过
            skip_findings.append({
                "skipped_step": step_list[skip_idx].get("name", f"step_{skip_idx}"),
                "result": "跳过此步骤后流程仍然成功 → 可能存在流程绕过",
                "final_status": skip_results[-1].get("status") if skip_results else None,
            })

    # 3. 步骤重放测试（重复执行最后一步）
    replay_findings: List[Dict] = []
    if len(step_list) >= 2:
        last_step = step_list[-1]
        replay_result = await _execute_step(last_step)
        if replay_result.get("status") == 200:
            replay_findings.append({
                "replayed_step": last_step.get("name", "last_step"),
                "result": "重复执行最后一步仍然成功 → 可能存在重放漏洞",
                "status": replay_result.get("status"),
            })

    all_findings = skip_findings + replay_findings

    return {
        "success": True,
        "session_id": session_id,
        "total_steps": len(step_list),
        "baseline_flow": baseline_results,
        "skip_test_findings": skip_findings,
        "replay_test_findings": replay_findings,
        "findings_count": len(all_findings),
        "findings": all_findings,
        "extracted_variables": variables,
        "summary": f"流程测试完成: {len(step_list)}步骤, 跳过测试发现{len(skip_findings)}个问题, 重放测试发现{len(replay_findings)}个问题" if all_findings else f"流程测试完成: {len(step_list)}步骤, 未发现流程绕过",
    }


async def logic_session_close(session_id: str) -> Dict[str, Any]:
    """关闭指定会话,释放资源。参数: session_id(会话ID)"""
    sm = _get_session_manager()
    await sm.close_session(session_id)
    return {"success": True, "message": f"会话 {session_id} 已关闭"}


async def logic_session_cookies(session_id: str) -> Dict[str, Any]:
    """获取指定会话的当前Cookie和状态。参数: session_id(会话ID)"""
    sm = _get_session_manager()
    if session_id not in sm._sessions:
        return {"success": False, "error": f"会话 {session_id} 不存在"}
    session = sm.get_session(session_id)
    cookies = {}
    for cookie in session.cookie_jar:
        cookies[cookie.key] = cookie.value
    return {"success": True, "session_id": session_id, "cookies": cookies}
