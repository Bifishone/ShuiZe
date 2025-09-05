from setuptools import setup, find_packages

setup(
    name='Sublist3r',
    version='1.1',  # 版本升级
    python_requires='>=3.6',  # 最低支持Python 3.6
    install_requires=[
        'dnspython>=2.0.0',
        'requests>=2.25.1',
        'beautifulsoup4>=4.9.3',  # 新增依赖
        'colorama>=0.4.4'  # 确保Windows颜色支持
    ],
    packages=find_packages(),
    include_package_data=True,
    url='https://github.com/aboul3la/Sublist3r',
    license='GPL-2.0',
    description='Subdomains enumeration tool for penetration testers',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v2',
        'Operating System :: OS Independent',  # 支持更多系统
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Security',
    ],
    keywords='subdomain dns detection enumeration',
    entry_points={
        'console_scripts': [
            'sublist3r = sublist3r:main',  # 修正入口函数
        ],
    },
)