import tarfile
import requests
from lxml import etree
import json
import logging
import os
import base64
import time
import shutil
import configparser
import traceback
from jinja2 import Template
from cachetools import TTLCache
import gzip
from urllib.parse import unquote
import re


from flask import Flask, Response, request, make_response, stream_with_context

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
# app.logger.handlers[0].setFormatter(logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', encoding='utf-8'))
subconverter = "subconverter"

logging.basicConfig(
    level=(
        os.environ.get("LOGGING_LEVEL", logging.INFO)
        if os.environ.get("LOGGING_LEVEL", logging.INFO)
        else logging.INFO
    ),  # 设置日志记录的级别为 INFO
    format="%(asctime)s - %(levelname)s - %(message)s",
)  # 设置日志记录的格式


# 过期时间一小时
loginCahce = TTLCache(
    maxsize=10,
    ttl=28800
)
subCache = TTLCache(maxsize=10, ttl=300)
fileCache = TTLCache(maxsize=100, ttl=86400)

def get_session() -> requests.Session:
    if "login" not in loginCahce:
        init_session()
    return loginCahce["login"]

def login(
    session: requests.Session,
    email: str,
    passwd: str,
    domain: str,
) -> dict[str, any]:
    params: dict[str, str] = {"email": email, "passwd": passwd, "code": ""}
    url: str = "https://" + domain + "/auth/login"
    resp: requests.Response = session.post(url, params)
    logging.debug("login resp code: %s, text: %s", resp.status_code, resp.text)
    return json.loads(resp.text)

def init_session():
    email = os.environ.get("ZCSSR_USER_EMAIL")
    passwd = os.environ.get("ZCSSR_USER_PASSWD")
    domain = os.environ.get("ZCSSR_DOMAIN")
    _ = os.environ.get("SUBCONVERTER_URL")
    if not email:
        logging.error("ZCSSR_USER_EMAIL not set")
        exit(1)
    if not passwd:
        logging.error("ZCSSR_USER_PASSWD not set")
        exit(1)
    if not domain:
        logging.error("ZCSSR_DOMAIN not set")
        exit(1)
    session: requests.Session = requests.session()
    if login(session, email, passwd, domain=domain)["ret"] != 1:
        logging.error("zcssr 登录失败")
        loginCahce["login"] = session
        exit(1)


def init_subconverter():
    # 移动 subconverter 至上一层目录
    current_dir: str = os.getcwd()
    # bin_dir: str = os.path.join(current_dir, "bin")
    extract_folder: str = "subconverter"
    subconverter_dir: str = os.path.join(current_dir, extract_folder)
    subconverter_binary: str = os.path.join(current_dir, extract_folder, "subconverter")
    # 已存在跳过下载
    if not os.path.isfile(subconverter_binary):
        if os.path.exists(subconverter_dir):
            shutil.rmtree(subconverter_dir)
        logging.info("Downloading Subconverter ....")
        url: str = (
            # todo fork the meta subconverter to change the handler/interfaces.cpp simpleGenerator  hard-coded expand=true
            # https://github.com/MetaCubeX/subconverter/releases/download/Alpha/subconverter_linux64.tar.gz
            "https://github.com/tindy2013/subconverter/releases/download/v0.9.0/subconverter_linux64.tar.gz"
            if not os.environ.get("SUBCONVERTER_DOWNLOAD_URL")
            else os.environ.get("SUBCONVERTER_DOWNLOAD_URL")
        )
        filename: str = "subconverter_linux64.tar.gz"
        response = requests.get(url)
        with open(filename, "wb") as f:
            f.write(response.content)

        logging.info("Downloaded Subconverter ....")

        with tarfile.open(filename, "r:gz") as tar:
            tar.extractall()
        os.remove(filename)
    global subconverter
    subconverter = subconverter_binary
    logging.info("new subconverter {}".format(subconverter))
    if not os.path.isfile(subconverter):
        exit(1)
    # os.system('{subconverter} -g &')


def replace_domain(url: str, new_domain: str):
    # 检查 URL 是否以 "https://" 开头
    if url.startswith("https://"):
        # 找到第一个 "/" 后的位置
        index = url.find("/", len("https://"))
        if index != -1:
            # 将域名替换为新的域名
            return "https://" + new_domain + url[index:]
    # 如果 URL 不以 "https://" 开头，或者找不到 "/"，则返回原始 URL
    return url


def get_sub_from_dom(dom: any, xpath: str) -> str | None:
    dom_nodes: list[any] = dom.xpath(xpath)
    if len(dom_nodes) > 0:
        return dom_nodes[0]
    return None


def get_sub_urls(session: requests.Session, domain: str) -> list[str]:
    url: str = "https://" + domain + "/user"
    resp: requests.Response = session.get(url=url)
    logging.debug("get sub urls resp: {}".format(resp.text))
    dom: any = etree.HTML(resp.text)
    urls = []

    v2ray_sub: str = get_sub_from_dom(
        dom, '//a[contains(.//text(), "V2Ray")]/@data-clipboard-text'
    )
    if not v2ray_sub:
        logging.error("failed get v2ray sub from dom, the dom is {}".format(resp.text))
        return []
    ssr_sub: str = get_sub_from_dom(
        dom, '//a[contains(.//text(), "SSR")]/@data-clipboard-text'
    )
    if not ssr_sub:
        logging.error("failed get ssr sub from dom, the dom is {}".format(resp.text))
        return []
    logging.debug("user info page: {}".format(resp.text))
    logging.info("v2ray sub url {}".format(v2ray_sub))
    logging.info("ssr sub url {}".format(ssr_sub))
    urls = []
    urls.append(v2ray_sub)
    # urls.append(ssr_sub)
    if os.environ.get("ZCSSR_SUB_USE_DOMAIN") == "true":
        for i in range(len(urls)):
            urls[i] = replace_domain(urls[i], os.environ.get("ZCSSR_DOMAIN"))
            logging.info("new sub url {}".format(urls[i]))
    return urls


exclude_nodes = "流量|过期时间|地址|故障"


def genereate_merge_sub_content(
    session: requests.Session, sub_urls: list[str], extend_sub_nodes: list[str]
) -> dict[str, str]:
    node_list: list[str] = []
    subUserInfo: str = ""
    for sub_url in sub_urls:
        print(sub_url)
        try:
            resp: requests.Response = session.get(url=sub_url)
            if resp.ok is False:
                raise Exception("get sub url content error, url: {}".format(sub_url))
            if len(subUserInfo) == 0:
                subUserInfo = resp.headers.get("Subscription-Userinfo")
            logging.debug("resp : {}".format(resp.text))
            decodeContent: str = str(base64.b64decode(resp.text), "utf-8")
            current_node_list: list[str] = decodeContent.strip().split("\n")
            node_list = node_list + current_node_list
        except Exception as e:
            logging.error("request sub url error", e)

    # remove nodes
    pattern = re.compile(exclude_nodes)
    for node in node_list[:]:
        content: str = unquote(node)
        if node.startswith("vmess://"):
            # 如果以 vmess:// 开头，截取 vmess:// 后的字符串
            encoded_content = node[len("vmess://") :]
            # 解码获取内容
            try:
                content = base64.b64decode(encoded_content).decode("utf-8")
            except Exception as e:
                logging.error("base64 decode node error", e)
            # 匹配正则表达式
        matches = pattern.findall(content)
        if matches:
            # 如果匹配成功，则移除该元素
            node_list.remove(node)

    if len(extend_sub_nodes) != 0:
        logging.info("extend sub nodes len {}".format(len(extend_sub_nodes)))
        node_list: list[str] = extend_sub_nodes + node_list

    logging.info("merged {} sub nodes".format(len(node_list)))
    encodeContent: str = str(base64.b64encode("\n".join(node_list).encode()), "utf-8")
    logging.debug("genereate merge sub node list {}".format(node_list))
    resp = {"Subscription-Userinfo": subUserInfo, "content": encodeContent}
    return resp


def generate_config_ini(block: str, params: dict[str, str]):
    generate_config_file: str = "./subconverter/generate.ini"
    generate_config_lock_file: str = "./subconverter/generate.ini.lock"
    if os.path.exists(generate_config_lock_file):
        raise Exception("Subconverter Last Job Not Completed")
    with open(generate_config_lock_file, "w") as lock:
        lock.write("1")
    config = configparser.ConfigParser()
    if os.path.exists(generate_config_file):
        with open(generate_config_file, "r") as configfile:
            config.read_file(configfile)
    logging.info("config {}".format(config))
    try:
        if config.has_section(block):
            config.remove_section(block)
        config.add_section(block)
        for k, v in params.items():
            config.set(block, k, v)
        with open(generate_config_file, "w") as configfile:
            config.write(configfile)
    except Exception as e:
        logging.error("read generetae.ini config failed", e)

    logging.info(f'{subconverter} -g --artifact "{block}')
    exitCode: int = os.system(f"{subconverter} -g --artifact '{block}'")
    os.remove(generate_config_lock_file)
    if exitCode != 0:
        raise Exception("generate failed! exit code {}".format(exitCode))


# api


@app.errorhandler(Exception)
def handle_global_exception(e):
    logging.error(e)
    traceback.print_exc()
    return {"error": "An error occurred", "msg": str(e)}, 500





@app.get("/sub/links.txt")
def sub_links():
    ignore_extend: str = request.args.get("ignore_extend")
    only_extend: str = request.args.get("only_extend")
    merge_sub_content = {}
    if request.url in subCache:
        merge_sub_content = subCache[request.url]
    else:
        sess = get_session()
        sub_urls = get_sub_urls(session=sess, domain=os.environ.get("ZCSSR_DOMAIN"))
        if len(sub_urls) == 0:
            logging.error("获取 zcssr 订阅链接失败")
            exit(1)
        merge_sub_content = genereate_merge_sub_content(
            session=sess,
            sub_urls=sub_urls,
            extend_sub_nodes=(
                os.environ.get("EXTEND_SUB_NODES").strip().split("\n")
                if os.environ.get("EXTEND_SUB_NODES")
                else []
            ),
        )

    response = make_response(merge_sub_content["content"])
    response.headers["Subscription-Userinfo"] = merge_sub_content[
        "Subscription-Userinfo"
    ]
    # response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Type"] = "application/octet-stream; charset=utf-8"
    response.headers["Content-Length"] = len(merge_sub_content["content"])
    response.headers["Content-Disposition"] = (
        "attachment; filename=links-{}.txt".format(int(time.time()))
    )
    return response


def read_file_chunks(path):
    CHUNK_SIZE = 8192
    with open(path, "rb") as fd:
        while 1:
            buf = fd.read(CHUNK_SIZE)
            if buf:
                yield buf
            else:
                break


@app.get("/sub/normal-ruleset.yaml")
def sub_clash_normal_ruleset():
    url: str = "https://{}/sub/links.txt".format(request.host)
    resp = requests.get(
        "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/templates/Normal.example.yaml.j2"
    )
    template_string: str = resp.text
    template = Template(template_string)
    rendered_template = template.render(sub_url=url)
    resp = make_response(gzip.compress(rendered_template.encode("utf8")))
    resp.headers = {
        "Content-Encoding": "gzip",
        "Content-Type": "application/octet-stream; charset=utf-8",
        "Subscription-Userinfo": sub_links().headers["Subscription-Userinfo"],
        "Content-Disposition": "attachment; filename=normal-ruleset-{}.yaml".format(
            int(time.time())
        ),
    }
    return resp


@app.get("/sub/normal.yaml")
def sub_clash_normal():
    path_name: str = "normal-{}.yaml".format(int(time.time()))
    cache_dir: str = os.path.join(os.getcwd(), "caches")
    full_path_name: str = os.path.join(cache_dir, path_name)
    if request.url in fileCache:
        data = fileCache[request.url]
        full_path_name = data["path"]
    else:
        url: str = "http://{}/sub/links.txt".format(request.host)
        config_name: str = "clashnoraml"
        if not os.path.exists(cache_dir):
            os.mkdir(cache_dir)
        generate_config_ini(
            config_name,
            params={
                "exclude": exclude_nodes,
                "path": full_path_name,
                "target": "clash",
                "url": url,
                "scv": "false",
                # "classic": "true",
                "new_name": "true",
                # "expand": "false",
                "config": "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/config/Normal.ini",
                # "config": "/home/hzhq/Workspace/MyProjects/my-clash-config-rule/clash/config/Normal.ini"
            },
        )
        fileCache[request.url] = {
            "path": full_path_name,
        }
    with open(full_path_name, "r") as f:
        content = gzip.compress(f.read().encode("utf8"))
    return Response(
        content,
        headers={
            "Content-Encoding": "gzip",
            "Content-Type": "application/octet-stream; charset=utf-8",
            "Subscription-Userinfo": sub_links().headers["Subscription-Userinfo"],
            "Content-Disposition": "attachment; filename={}".format(path_name),
        },
    )


@app.get("/sub/surfboard.txt")
def sub_sufboard():
    path_name: str = "surfboard-{}.txt".format(int(time.time()))
    cache_dir: str = os.path.join(os.getcwd(), "caches")
    full_path_name: str = os.path.join(cache_dir, path_name)
    if request.url in fileCache:
        data = fileCache[request.url]
        full_path_name = data["path"]
    else:
        url: str = "http://{}/sub/links.txt".format(request.host)
        config_name: str = "surfboard"
        if not os.path.exists(cache_dir):
            os.mkdir(cache_dir)
        generate_config_ini(
            config_name,
            params={
                "exclude": exclude_nodes,
                "path": full_path_name,
                "target": "surfboard",
                "url": url,
                "scv": "false",
                # "classic": "true",
                "new_name": "true",
                # "expand": "false",
                "config": "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/config/Normal.ini",
            },
        )

        with open(full_path_name, "r+") as file:
            lines = file.readlines()
            managed_info = "#!MANAGED-CONFIG {} interval=86400 strict=false".format(
                request.url
            )
            if len(lines) > 0 and lines[0].startswith("#!MANAGED-CONFIG"):
                lines[0] = managed_info
                file.seek(0, 0)
                file.write("".join(lines))
            else:
                file.seek(0, 0)
                file.write(managed_info + "\n" + "".join(lines))
        fileCache[request.url] = {
            "path": full_path_name,
        }
    with open(full_path_name, "r") as f:
        content = gzip.compress(f.read().encode("utf8"))
    return Response(
        content,
        headers={
            "Content-Encoding": "gzip",
            "Content-Type": "application/octet-stream; charset=utf-8",
            "Subscription-Userinfo": sub_links().headers["Subscription-Userinfo"],
            "Content-Disposition": "attachment; filename={}".format(path_name),
        },
    )


if __name__ == "__main__":
    init_session()
    init_subconverter()
    if os.environ.get("FLASK_ENV") == "production":
        from waitress import serve

        serve(app, host="0.0.0.0", port=5000)
    else:
        app.run(host="0.0.0.0", debug=True)
