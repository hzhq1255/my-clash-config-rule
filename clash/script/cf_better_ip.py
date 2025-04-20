
import base64
import requests
import json
import yaml
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
from collections import defaultdict


# 定义数据结构
@dataclass
class IpItem:
    name: str
    ip: str
    colo: str
    speed: int
    uptime: int


@dataclass
class IpData:
    v4: Dict[str, List[IpItem]] = field(default_factory=dict)
    v6: Dict[str, List[IpItem]] = field(default_factory=dict)

    @staticmethod
    def from_dict(data: dict) -> "IpData":
        """直接从 JSON dict 转换"""
        fields = ["ip", "name", "colo", "speed", "uptime"]
        v4 = {
            k: [IpItem(**{k: v for k, v in item.items() if k in fields}) for item in v]
            for k, v in data.get("data", {}).get("v4", {}).items()
        }
        v6 = {
            k: [IpItem(**{k: v for k, v in item.items() if k in fields}) for item in v]
            for k, v in data.get("data", {}).get("v6", {}).items()
        } if "v6" in data.get("data", {}) else {}

        return IpData(v4=v4, v6=v6)

class TelecomOperator(Enum):
    CM = ("移动", "CM")
    CU = ("联通", "CU")
    CT = ("电信", "CT")

    def __new__(cls, chinese_name, full_name):
        obj = object.__new__(cls)
        obj._value_ = chinese_name  # 设定枚举的默认值
        obj.chinese_name = chinese_name
        obj.full_name = full_name
        return obj

def get_better_cf_ips() -> Optional[IpData]:
    url = "https://api.vvhan.com/tool/cf_ip"
    headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Connection": "keep-alive",
        "Origin": "https://cf.vvhan.com",
        "Referer": "https://cf.vvhan.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Microsoft Edge";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "Windows"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=30,verify=True)  # 10 秒超时
        response.raise_for_status()
        data = response.json()
        print(f"get better cf ips, data: {data}")
        return IpData.from_dict(data)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Cloudflare IPs: {e}")
        return None

def get_ipv4_addresses(ip_data: IpData, operators: List[TelecomOperator]) -> List[IpItem]:
    ipv4_addresses = []
    for operator in operators:
        ipv4_addresses.extend([item for item in ip_data.v4.get(operator.full_name, [])])
    return ipv4_addresses

def filter_ipv4_addresses_by_speed(ip_data: IpData, operators: List[TelecomOperator]) -> List[IpItem]:
    min_speed = 1500
    ipv4_addresses = get_ipv4_addresses(ip_data, operators)
    ipv4_addresses = [item for item in ipv4_addresses if item.speed >= min_speed]
    return ipv4_addresses


def group_ipv4_addresses_by_name(ipv4_addresses: List[IpItem]) -> Dict[str, List[IpItem]]:
    grouped_ipv4_addresses = defaultdict(list)
    for item in ipv4_addresses:
        grouped_ipv4_addresses[item.name].append(item)
    return grouped_ipv4_addresses

def parse_vmess_subscription(subscription: str) -> dict:
    # decode subscription
    print(f"parse vmess subscription, subscription: {subscription}")
    vmess_protocol = "vmess://"
    if not subscription.startswith(vmess_protocol):
        return {}
    subscription = subscription[len(vmess_protocol):]
    return json.loads(base64.b64decode(subscription).decode('utf-8'))

def generate_bf_ip_vmess_proxies_yaml(proxy: dict, ip_data: IpData, operators: List[TelecomOperator]) -> List[dict]:
    ipv4_addresses = filter_ipv4_addresses_by_speed(ip_data, operators)
    grouped_ipv4_addresses = group_ipv4_addresses_by_name(ipv4_addresses)
    proxies = []
    for name,items in grouped_ipv4_addresses.items():
        cnt = 0
        for item in items:
            cnt += 1
            proxies.append({
                "name": f"{name}-{cnt}",
                "server": item.address,
                "port": proxy["port"],
                "type": "vmess",
                "uuid": proxy["id"],
                "alterId": proxy["aid"],
                "cipher": proxy["scy"],
                "tls": proxy["tls"] == "true",
                "skip-cert-verify": proxy["verify_cert"] == "true",
                "servername": proxy["add"],
                "network": proxy["net"],
                "ws-opts": {
                    "path": proxy["path"],
                    "headers": {
                        "Host": proxy["host"],
                    },
                }
            })
    return proxies    

def generate_bf_ip_vmess_proxies(proxy: dict, ip_data: IpData, operators: List[TelecomOperator]) -> List[dict]:
    ipv4_addresses = filter_ipv4_addresses_by_speed(ip_data, operators)
    grouped_ipv4_addresses = group_ipv4_addresses_by_name(ipv4_addresses)
    proxies = []
    for name,items in grouped_ipv4_addresses.items():
        cnt = 0
        for item in items:
            cnt += 1
            proxies.append({
                "v": "2",
                "ps": f"{name}-{cnt}",
                "add": item.ip,
                "port": proxy["port"],
                "id": proxy["id"],
                "aid": proxy["aid"],
                "scy": proxy["scy"],
                "net": proxy["net"],
                "type": proxy["type"],
                "host": proxy["host"],
                "path": proxy["path"],
                "tls": proxy["tls"],
                "sni": proxy["sni"],
                "alpn": proxy["alpn"],
                "fp": proxy["fp"]
            })
    return proxies



# convert vmess subscription to proxies
def convert_vmess_subscription_to_cf_ip_vmess_proxies(subscription_base64: str, file_type: str) -> str:
    subscription = parse_vmess_subscription(subscription_base64)
    print(f"convert vmess subscription to proxies, subscription: {subscription}")
    if not subscription:
        return ""
    better_cf_ips = get_better_cf_ips()
    print(f"get better cf ips: {better_cf_ips}")
    if not better_cf_ips:
        return ""
    proxies = generate_bf_ip_vmess_proxies(subscription, better_cf_ips, [TelecomOperator.CM, TelecomOperator.CU, TelecomOperator.CT])
    vmess_config_list = []
    for proxy in proxies:
        vmess_config = json.dumps(proxy)
        base64_vmess_config = str(base64.b64encode(vmess_config.encode()), 'utf-8')
        vmess_config_list.append(f"vmess://{base64_vmess_config}")            
    sub_str = '\n'.join(vmess_config_list)
    # convert sub_str to base64

    proxies_yaml = generate_bf_ip_vmess_proxies_yaml(subscription, better_cf_ips, [TelecomOperator.CM, TelecomOperator.CU, TelecomOperator.CT])
    proxies_yaml_str = yaml.dump({
            "proxies": proxies
        }, allow_unicode=True)
    print(f"convert vmess subscription to proxies yaml, content: {proxies_yaml_str}")
    sub_result = str(base64.b64encode(sub_str.encode()), 'utf-8')
    if file_type == 'yaml':
        sub_result = proxies_yaml_str
    print(f"convert vmess subscription to proxies, sub_result: {sub_result}")
    return sub_result


if __name__ == '__main__':
    better_cf_ips = get_better_cf_ips()
    if better_cf_ips:
        proxies = generate_bf_ip_vmess_proxies_yaml(better_cf_ips, [TelecomOperator.CM, TelecomOperator.CU, TelecomOperator.CT])
        # convert proxies to yaml
        proxies_yaml = yaml.dump({
            "proxies": proxies
        }, allow_unicode=True)
        # write proxies to file
        with open("bf_ip_vmess_proxies.yaml", "w", encoding="utf-8") as f:
            f.write(proxies_yaml)

        
        proxies = generate_bf_ip_vmess_proxies(better_cf_ips, [TelecomOperator.CM, TelecomOperator.CU, TelecomOperator.CT])
        vmess_config_list = []
        for proxy in proxies:
            vmess_config = json.dumps(proxy)
            base64_vmess_config = str(base64.b64encode(vmess_config.encode()), 'utf-8')
            vmess_config_list.append(f"vmess://{base64_vmess_config}")            
        with open("bf_ip_vmess_proxies.txt", "w", encoding="utf-8") as f:
            content = '\n'.join(vmess_config_list)
            f.write(content)

            
