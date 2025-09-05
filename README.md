

# Hakutaku (ShuiZe轻量化优化版)

**基于 [0x727/ShuiZe_0x727](https://github.com/0x727/ShuiZe_0x727) 二次开发 | 作者：一只鱼（Bifishone） | 仓库地址：[Bifishone/ShuiZe](https://github.com/Bifishone/ShuiZe)**

<img width="997" height="575" alt="images" src="https://github.com/user-attachments/assets/9269a7ac-e323-409a-b60b-e7bca584d7cd" />


------

## 项目介绍

本项目是对原ShuiZe工具的轻量化优化版本，旨在通过**剔除冗余功能、优化输出体验、聚焦核心能力**，提供更高效、易用的信息收集工具，适用于授权场景下的资产探测与信息梳理。（同时也保留了ShuiZe的核心功能）

------

## 核心功能

### 1. 子域名探测

- 整合 `ksubdomain`、`theHarvester` 等工具实现多源探测
- 调用 VirusTotal、ThreatCrowd 等 API 补充子域名数据
- 百度 / 必应爬虫辅助抓取关联子域名
- 从 HTTPS 证书中提取隐藏 DNS 信息

### 2. 网络基础探测

- 自动检测 DNS 泛解析，过滤无效信息
- 批量解析子域名 A 记录，区分 CDN 与真实 IP
- 分析目标 IP 高频 C 段，辅助扩大探测范围
- 支持 HOST 碰撞发现隐藏资产

### 3. 信息拓展与聚合

- 备案反查关联顶级域名
- 爱企查接口获取企业架构、投资关系
- GitHub 敏感信息挖掘（关键词匹配密钥、邮箱等）
- IP 反查域名，拓展资产边界

### 4. 结果输出与整理

- Excel 结构化存储（子域名、IP、服务等分类工作表）
- 终端彩色分级输出（成功 / 警告 / 错误信息区分）
- 自动验证 Web 服务存活状态，过滤无效资产

------

## 安装与使用

### 环境要求

- Python 3.8 及以上
- 依赖库：见项目 `requirements.txt`

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/Bifishone/ShuiZe.git
cd ShuiZe

# 安装依赖
pip install -r requirements.txt
```

### 常用命令

| 命令                                                   | 功能说明                     |
| ------------------------------------------------------ | ---------------------------- |
| `python Hakutaku.py -h`                                | 查看帮助文档                 |
| `python Hakutaku.py -d example.com`                    | 对目标域名进行全流程信息收集 |
| `python Hakutaku.py -d example.com --justInfoGather 1` | 仅收集信息，不进行漏洞检测   |
| `python Hakutaku.py -c 192.168.1.0`                    | 对指定 C 段进行资产探测      |

------

## 优化亮点

1. **轻量化**：剔除冗余模块，降低资源占用，提升运行效率
2. **输出美化**：新增 `ColorPrinter` 类，终端信息层级更清晰
3. **Bug 修复**：解决原工具 DNS 解析超时、泛解析误判等问题
4. **结果优化**：Excel 表结构调整，便于快速筛选关键信息

------

## 免责声明

1. 本工具仅用于**合法授权**的网络安全测试、漏洞评估等场景，严禁用于未经授权的攻击行为。
2. 使用本工具即表示您已充分了解并同意遵守《网络安全法》等相关法律法规，对自身操作承担全部责任。
3. 作者不对因滥用本工具造成的任何直接或间接损失承担法律责任。
4. 如发现违规使用行为，作者保留追究相关责任的权利。

------

## 致谢

- **原作者**：[0x727](https://github.com/0x727) 提供基础框架与核心功能
- 所有为本项目提供反馈与建议的安全爱好者
