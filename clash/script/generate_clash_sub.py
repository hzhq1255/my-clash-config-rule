import os
import subprocess
import time
import urllib.parse
import requests as req
import json
import base64


def login(email, passwd, url):
    params = {
        'email': email,
        'passwd': passwd,
        'code': ''
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 Edg/90.0.818.62"
    }
    response = session.post(url, params, headers).text
    return json.loads(response)


def get_vmess_links(url):
    response = session.get(url).text
    # base64 解码
    response = str(base64.b64decode(response), 'utf-8')
    vmess_link_list = response.strip().split("\n")
    # 移除前两行 无用的节点
    # vmess_link_list = vmess_link_list[2:]
    return vmess_link_list


def get_ssr_links(url):
    return []


def get_my_links():
    my_links = []
    return my_links


def write_my_sub(sub_links, domain):
    domain_path = "/www/wwwroot/{}/".format(domain)
    sub_file_name = "links.txt"
    text = '\n'.join(sub_links)
    with open(domain_path + sub_file_name, 'w', encoding='utf-8') as f:
        f.write(str(base64.b64encode(text.encode()), 'utf-8'))


def start_subconverter():
    docker_image = 'tindy2013/subconverter'
    docker_image_tag = '0.7.2'
    proc = subprocess.Popen("docker ps -a | grep 0.0.0.0:25500", shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            encoding="utf-8")
    count = 0
    stdout_text = ""
    for line in proc.stdout.readlines():
        count = count + 1
        stdout_text = line
    if count == 1 and stdout_text.find("Up") == -1:
        os.system("docker rm -f $(docker ps -a | grep 0.0.0.0:25500 | awk '{print $1}')")
        os.system("docker rm -f subconverter")
    elif count == 1 and stdout_text.find('Up') != -1:
        print('subconverter server is running')
        return 1
    os.system(
        "docker run -d --restart=always --name subconverter -p 25500:25500 {}:{}".format(
            docker_image, docker_image_tag))
    print('subconverter server started')
    return 1


def update_subscription(subconverter_url, params, sub_file):
    param_str = "?"
    for k, v in params.items():
        param_str = param_str + k + "=" + v + "&"
    if param_str == "?":
        param_str = ""
    else:
        param_str = param_str[:len(param_str) - 1]
    req_sub_url = subconverter_url + param_str
    print(req_sub_url)
    response = session.get(req_sub_url)
    with open(sub_file, 'wb') as f:
        f.write(response.content)


def generate_config_yaml(path, filename, config_url, domain):
    req_params = {
        'target': 'clash',
        'url': urllib.parse.quote_plus("https://{}/links.txt".format(domain)),
        'config': urllib.parse.quote_plus(config_url)
    }
    print(req_params)
    sub_file = path + '/' + filename
    update_subscription(subconverter_server, req_params, sub_file)
# ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpxUTdyQXJ3MUM0NE00cGRo%40myvmess.hzhq1255.work%3A443%2F%3Fplugin%3Dv2ray-plugin%3Btls%3Bmode%3Dwebsocket%3Bpath%3D%2Ffh39vgtydu36cajnkvdb%3Bhost%3Dmyvmess.hzhq1255.work%23%28US%29rackseattle-ss

if __name__ == '__main__':
    zcssr_home = "https://sub.com"
    my_domain = "www.yourdomain.com"
    req.adapters.DEFAULT_RETRIES = 5
    session = req.session()
    session.keep_alive = False
    vmess_sub_url = zcssr_home + "/link"
    login_url = zcssr_home + "/auth/login"
    # clash_config_url = "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/config" \
    #                    "/Full_Adblock.ini"
    full_config = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_AdblockPlus.ini"
    normal_config = "https://raw.githubusercontent.com/hzhq1255/my-clash-config-rule/master/clash/config/Normal.ini"
    subconverter_server = "http://localhost:25500/sub"
    my_email = "youraccount"
    my_password = "yourpassword"
    start_subconverter()
    login_res = login(my_email, my_password, login_url)
    if login_res['ret'] == 1:
        vmess_links = get_vmess_links(vmess_sub_url)
        my_links = get_my_links()
        links = vmess_links[0:2] + my_links + vmess_links[2:]
        write_my_sub(links, my_domain)
        generate_config_yaml("/www/wwwroot/{}/".format(my_domain), 'full.yaml'.format(int(time.time())), full_config, my_domain)
        generate_config_yaml("/www/wwwroot/{}/".format(my_domain), 'normal.yaml'.format(int(time.time())), normal_config, my_domain)
    else:
        print("登录失败")


