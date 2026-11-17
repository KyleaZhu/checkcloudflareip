#!/usr/bin/env python3
"""
通过 Cloudflare Worker（Check_Proxy.js）批量探测「IP:端口 能不能反代 CF」。

用法：
    python probe_ip.py                              # 读 ip.txt，写 bestip_worker.txt
    python probe_ip.py --input a.txt --best b.txt

ip.txt 格式：每行一个 CIDR 或单个 IP，支持 # 注释，例如
    1.0.0.0/24
    5.10.214.0/23
    # 整行注释会被忽略

输出：
    bestip_worker.txt   只保留 ok 的 IP，按 ip.txt 里的顺序，每行 ip#机房代码
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

WORKER = "https://123.xdu.qzz.io"

# Worker 侧没有鉴权但有 WAF：python-urllib 的默认 UA 会被 1010 拦掉，必须伪装。
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) cf-probe-runner/1.0"

BATCH_SIZE = 24          # 每批候选数 = Worker 单请求子请求上限(实测 48) / 每个候选的探测路数(2: ipsb + trace)
CONCURRENCY = 4          # 同时发几个请求（实测 4 之后收益递减）
PORT = 443               # 固定探测端口
TIMEOUT_MS = 1500        # Worker 侧单次探测超时（毫秒）；实测成功 connect 最长 188ms
HTTP_TIMEOUT = 45        # 单次 HTTP 请求超时（秒），要大于 timeoutMs*2
RETRIES = 2              # 429/5xx/网络错误时的重试次数
MAX_IPS = 500_000        # 安全阀：展开后超过这个数就中止，防止误贴 10.0.0.0/8

PROBE_FROM = "cf-edge"   # 标记观测点，避免和本地/其他环境的结果混在一起比较


# ============================ 输入解析 ============================

def parse_line(raw: str) -> str | None:
    """解析一行：返回 CIDR 字符串，空行/注释返回 None。"""
    line = raw.split("#", 1)[0].strip()
    return line or None


def expand_targets(path: str) -> list[str]:
    """展开所有 CIDR，跨行去重（重叠段是这类脚本最常见的浪费来源）。"""
    targets: list[str] = []
    seen: set[str] = set()
    skipped_private = 0
    duplicated = 0

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            cidr = parse_line(raw)
            if cidr is None:
                continue

            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                print(f"[跳过] 无法解析 {cidr!r}: {exc}", file=sys.stderr)
                continue

            if network.is_private or network.is_loopback or network.is_link_local:
                skipped_private += len(list(network.hosts())) or 1
                print(f"[跳过] 私有/本地段无意义: {network}", file=sys.stderr)
                continue

            for host in network.hosts():
                ip = str(host)
                if ip in seen:
                    duplicated += 1
                    continue
                seen.add(ip)
                targets.append(ip)

            if len(targets) > MAX_IPS:
                raise SystemExit(
                    f"展开后超过 {MAX_IPS} 个 IP，已中止。请检查 ip.txt 是否误贴了大段。"
                )

    if duplicated:
        print(f"[去重] 跳过了 {duplicated} 个重复 IP（CIDR 之间有重叠）", file=sys.stderr)
    if skipped_private:
        print(f"[跳过] {skipped_private} 个私有/本地地址", file=sys.stderr)

    return targets


# ============================ Worker 调用 ============================

def http_get_json(url: str) -> object:
    """带 UA 与重试的 GET；返回解析后的 JSON。"""
    last_error = "unknown"
    for attempt in range(RETRIES + 1):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read()[:200].decode("utf-8", "replace")
            last_error = f"HTTP {exc.code}: {body}"
            if exc.code == 403 and "1010" in body:
                last_error += "（UA 被 WAF 拦截，检查 USER_AGENT）"
            # 4xx 除 429 外重试没意义
            if 400 <= exc.code < 500 and exc.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < RETRIES:
            time.sleep(1.5 * (attempt + 1))

    raise RuntimeError(last_error)


def pick_exit(probe_results: list[dict]) -> dict:
    """从两路上游探测里挑一条成功的，取出口信息。"""
    for probe in probe_results:
        if probe.get("ok"):
            return probe
    return probe_results[0] if probe_results else {}


def probe_batch(batch: list[str]) -> list[dict]:
    """一次请求探测一批候选，返回每个 IP 的归一化记录。"""
    candidates = ",".join(f"{ip}:{PORT}" for ip in batch)
    url = f"{WORKER.rstrip('/')}/probe?candidates={candidates}&timeoutMs={TIMEOUT_MS}"

    try:
        payload = http_get_json(url)
    except RuntimeError as exc:
        # 整批失败也要保留记录，否则统计和退出码无从判断
        return [
            {"ip": ip, "ok": False, "error": f"batch failed: {exc}"}
            for ip in batch
        ]

    items = payload if isinstance(payload, list) else [payload]
    by_candidate = {str(item.get("candidate", "")): item for item in items if isinstance(item, dict)}

    records: list[dict] = []
    for ip in batch:
        key = f"{ip}:{PORT}"
        item = by_candidate.get(key, {})
        results = item.get("probe_results") or []
        chosen = pick_exit(results)

        errors = [
            f"{probe.get('probe_name')}: {probe.get('error')}"
            for probe in results
            if not probe.get("ok") and probe.get("error")
        ]

        records.append(
            {
                "ip": ip,
                "ok": bool(item.get("ok")),
                "exit_country": chosen.get("exit_country"),
                "edge_colo": item.get("edge_colo"),
                "error": "; ".join(errors) if errors else (None if item else "missing in response"),
            }
        )

    return records


# ============================ 输出 ============================

def write_best(records: list[dict], best_path: str) -> None:
    ok_records = [r for r in records if r.get("ok")]

    if not ok_records:
        # 关键：空结果绝不覆盖旧文件（main.py 就是这么把 bestip.txt 清空的）
        if os.path.exists(best_path):
            print(f"[警告] 没有任何 IP 通过探测，保留 {best_path} 的旧内容不覆盖。", file=sys.stderr)
        else:
            # 首次运行就全未通过时，仍要落一个空文件：
            # 否则后续 git add 会因 pathspec 不存在而整步失败（exit 128）
            with open(best_path, "w", encoding="utf-8", newline="\n"):
                pass
            print(f"[警告] 没有任何 IP 通过探测，已创建空的 {best_path}。", file=sys.stderr)
        return

    with open(best_path, "w", encoding="utf-8", newline="\n") as fh:
        for record in ok_records:
            fh.write(f"{record['ip']}#{record.get('edge_colo') or ''}\n")


def write_summary(records: list[dict], elapsed: float) -> None:
    ok_records = [r for r in records if r.get("ok")]
    countries: dict[str, int] = {}
    for record in ok_records:
        country = record.get("exit_country") or "?"
        countries[country] = countries.get(country, 0) + 1

    lines = [
        "## CF 反代探测结果",
        "",
        f"- 观测点：`{PROBE_FROM}`（Cloudflare Worker）",
        f"- 探测总数：**{len(records)}**",
        f"- 通过：**{len(ok_records)}**（{len(ok_records) / len(records) * 100:.1f}%）" if records else "- 无数据",
        f"- 总耗时：{elapsed:.1f}s",
        "",
    ]

    if countries:
        lines += ["### 出口国家分布", "", "| 国家 | 数量 |", "|---|---|"]
        for country, count in sorted(countries.items(), key=lambda kv: -kv[1])[:10]:
            lines.append(f"| {country} | {count} |")
        lines.append("")

    text = "\n".join(lines)
    print(text)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


# ============================ 主流程 ============================

def main() -> int:
    parser = argparse.ArgumentParser(description="通过 CF Worker 批量探测 IP 能否反代 CF")
    parser.add_argument("--input", default="ip.txt", help="输入文件（默认 ip.txt）")
    parser.add_argument("--best", default="bestip_worker.txt", help="可用 IP 输出（默认 bestip_worker.txt）")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"找不到输入文件 {args.input}", file=sys.stderr)
        return 2

    targets = expand_targets(args.input)
    if not targets:
        print("ip.txt 里没有可探测的目标。", file=sys.stderr)
        return 2

    batches = [targets[i: i + BATCH_SIZE] for i in range(0, len(targets), BATCH_SIZE)]
    print(
        f"开始探测 {len(targets)} 个 IP，分 {len(batches)} 批，"
        f"每批 {BATCH_SIZE} 个，并发 {CONCURRENCY}，Worker={WORKER}",
        file=sys.stderr,
    )

    started = time.time()
    records: list[dict] = []
    finished = 0

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {pool.submit(probe_batch, batch): batch for batch in batches}
        for future in as_completed(futures):
            records.extend(future.result())
            finished += 1
            if finished % 10 == 0 or finished == len(batches):
                done = sum(1 for r in records if r.get("ok"))
                print(
                    f"  进度 {finished}/{len(batches)} 批，已完成 {len(records)} 个，通过 {done} 个",
                    file=sys.stderr,
                )

    elapsed = time.time() - started
    order = {ip: idx for idx, ip in enumerate(targets)}
    records.sort(key=lambda r: order.get(r["ip"], 1 << 30))

    write_best(records, args.best)
    write_summary(records, elapsed)

    ok_count = sum(1 for r in records if r.get("ok"))
    # 全部批次都失败（比如 Worker 挂了、UA 被拦）时，用非零退出码让 Actions 变红
    if ok_count == 0 and records and all("batch failed" in (r.get("error") or "") for r in records):
        print("所有批次请求都失败，请检查 Worker 是否可用、UA 是否被 WAF 拦截。", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
