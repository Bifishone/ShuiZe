import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import quote
import argparse
from termcolor import cprint
import warnings

# 忽略SSL证书验证警告
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0'}


def beianbeianApi(domain):
    cprint('Load beianbeianApi: ', 'green')
    beianId = ''
    url = f'http://www.beianbeian.com/s-0/{domain}.html'
    try:
        res = requests.get(
            url=url,
            headers=headers,
            allow_redirects=False,
            verify=False,
            timeout=10
        )
        res.raise_for_status()  # 检查HTTP错误状态
    except requests.exceptions.RequestException as e:
        print(f'[error] http://www.beianbeian.com 请求失败: {str(e)}')
        return []

    soup_1 = BeautifulSoup(res.text, 'html.parser')
    tbodys = soup_1.find_all('tbody', id='table_tr')
    for tbody in tbodys:
        a_hrefs = tbody.find_all('a')
        for a_href in a_hrefs:
            if '反查' in a_href.get_text():
                beianId = a_href.get('href', '')

    if not beianId:
        print('没有匹配到备案号')
        return []

    beianSearchUrl = f'http://www.beianbeian.com{beianId}'
    print(f'查询到备案号: {beianSearchUrl}')

    beianbeianNewDomains = []
    tempDict = {}
    try:
        res = requests.get(
            url=beianSearchUrl,
            headers=headers,
            allow_redirects=False,
            verify=False,
            timeout=10
        )
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'[error] 请求 {beianSearchUrl} 失败: {str(e)}')
        return []

    soup = BeautifulSoup(res.text, 'html.parser')
    tbodys = soup.find_all('tbody', id='table_tr')
    for tbody in tbodys:
        trs = tbody.find_all('tr')
        for tr in trs:
            tds = tr.find_all('td')
            if len(tds) >= 7:  # 确保有足够的列
                companyName = tds[4].get_text(strip=True)
                newDomain = tds[5].get_text(strip=True).replace('www.', '')
                time = tds[6].get_text(strip=True)
                if newDomain and newDomain not in tempDict:
                    tempDict[newDomain] = (companyName, newDomain, time)
                    beianbeianNewDomains.append((companyName, newDomain, time))

    beianbeianNewDomains = list(set(beianbeianNewDomains))
    print(f'beianbeianApi去重后共计{len(beianbeianNewDomains)}个顶级域名')
    return beianbeianNewDomains


def chinazApi(domain):
    cprint('Load chinazApi: ', 'green')
    chinazNewDomains = []
    companyName = ""

    # 获取公司名
    url = f"https://micp.chinaz.com/?query={domain}"
    try:
        res = requests.get(
            url=url,
            headers=headers,
            allow_redirects=False,
            verify=False,
            timeout=10
        )
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'[error] 请求 {url} 失败: {str(e)}')
        return chinazNewDomains, companyName

    # 改进正则表达式，增强匹配能力
    company_match = re.search(
        r'<tr><td class="ww-3 c-39 bg-3fa">主办单位：</td><td class="z-tl">(.*?)</td></tr>',
        res.text,
        re.IGNORECASE | re.DOTALL
    )
    if company_match:
        companyName = company_match.group(1).strip()
    else:
        print(f"[{domain}] 没有匹配到公司名")
        return chinazNewDomains, companyName

    # 获取备案号
    url = f'https://micp.chinaz.com/Handle/AjaxHandler.ashx?action=GetBeiansl&query={domain}&type=host'
    try:
        res = requests.get(
            url=url,
            headers=headers,
            allow_redirects=False,
            verify=False,
            timeout=10
        )
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'[error] 请求 {url} 失败: {str(e)}')
        return chinazNewDomains, companyName

    # 改进备案信息提取正则
    beianResult = re.findall(
        r'SiteLicense:"([^"]*)",SiteName:"([^"]*)",MainPage:"([^"]*)",VerifyTime:"([^"]*)"',
        res.text
    )
    if not beianResult:
        print(f"[{domain}] 没有查到备案信息")
        return chinazNewDomains, companyName

    for item in beianResult:
        beianId, siteName, newDomain, time = item
        if newDomain.startswith('www.'):
            newDomain = newDomain.replace("www.", '', 1)  # 只替换一次
        if newDomain:  # 确保域名为非空
            chinazNewDomains.append([beianId, siteName, newDomain, time])

    return chinazNewDomains, companyName


def run_beian2domain(domain):
    """执行备案信息查询主函数"""
    beianNewDomains = []
    chinazNewDomains, companyName = chinazApi(domain)

    tempDict = {}
    for each in chinazNewDomains:
        if len(each) >= 3 and each[2] not in tempDict:  # 增加数据有效性检查
            tempDict[each[2]] = each
            beianNewDomains.append(each)

    cprint('-' * 50 + f'去重后共计{len(beianNewDomains)}个顶级域名' + '-' * 50, 'green')
    for domain_info in beianNewDomains:
        print(domain_info)

    cprint(f'去重后共计{len(beianNewDomains)}个顶级域名', 'red')
    return beianNewDomains, companyName


def main():
    """命令行参数解析与入口函数"""
    # 创建命令行参数解析器
    parser = argparse.ArgumentParser(description='通过备案信息查询关联域名')
    parser.add_argument('-d', '--domain', required=True, help='需要查询的主域名（例如：taobao.com）')

    # 解析参数
    args = parser.parse_args()

    # 执行查询
    run_beian2domain(args.domain)


if __name__ == '__main__':
    main()
