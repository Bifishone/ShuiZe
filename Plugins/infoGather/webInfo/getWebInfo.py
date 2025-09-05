import logging
from Plugins.infoGather.webInfo.Wappalyzer.Wappalyzer import Wappalyzer, WebPage
import warnings
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from Plugins.infoGather.webInfo.Xapp.XappApi import run_xapp

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 禁用安全请求警告
warnings.filterwarnings('ignore')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def run_getWebInfo(url):
    try:
        # 调用 run_xapp 获取信息
        info = run_xapp(url)
        if info:
            logging.info(f"成功获取 {url} 的信息: {info}")
            return str(info)
        else:
            logging.warning(f"未获取到 {url} 的有效信息")
    except requests.RequestException as req_err:
        logging.error(f"请求 {url} 时发生网络错误: {req_err}")
    except Exception as e:
        logging.error(f"处理 {url} 时发生未知错误: {e}")
    return None

if __name__ == '__main__':
    url = r''
    if url:
        info = run_getWebInfo(url)
        if info:
            print(info)
    else:
        logging.error("请提供有效的 URL")