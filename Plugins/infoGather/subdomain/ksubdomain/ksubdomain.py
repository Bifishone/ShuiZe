import os


def run_ksubdomain(domain):
    ksubdomains = []
    ksubdomain_folder = os.path.join(".", "Plugins", "infoGather", "subdomain", "ksubdomain")
    ksubdomain_file = os.path.join(ksubdomain_folder, f"{domain}.txt")

    try:
        # 移除chmod命令（Windows不支持）
        # 调整执行命令路径为Windows格式
        if os.name == "nt":  # 判断是否为Windows系统
            ksubdomain_cmd = os.path.join(ksubdomain_folder, "ksubdomain_windows.exe")
        else:  # Linux系统保留原逻辑
            ksubdomain_cmd = os.path.join(ksubdomain_folder, "ksubdomain_linux")
            os.system(f"chmod 777 {ksubdomain_cmd}")


        # 原作者的命令执行
        # os.system(f"{ksubdomain_cmd} -skip-wild -full -d {domain} -o {ksubdomain_file}")
        # 自己定义的命令-内置默认字典爆破
        # os.system(f"{ksubdomain_cmd} -d {domain} -o {ksubdomain_file}")
        os.system(f"echo \"该爆破工具已禁用，如有需要，请自行在代码中修改~\"")


        with open(ksubdomain_file, 'r', encoding='utf-8') as f:
            for line in f.readlines():
                line = line.strip()
                if "=>" in line:
                    subdomain = line.split("=>")[0].strip()
                    ksubdomains.append(subdomain)

        os.remove(ksubdomain_file)
    except Exception as e:
        ksubdomains = []

    return list(set(ksubdomains))
