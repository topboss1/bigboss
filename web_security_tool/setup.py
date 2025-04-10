from setuptools import setup, find_packages

setup(
    name="web_security_tool",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.1",
        "beautifulsoup4>=4.9.3",
        "paramiko>=2.7.2",
    ],
    python_requires=">=3.6",
    author="보안 테스트 팀",
    description="웹 애플리케이션 보안 취약점 검사 도구",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
) 