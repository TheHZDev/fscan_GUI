## fscan GUI外壳工具

本工具使用Python开发而成，基于GPL 3.0许可证发布。  
本工具的用途为快速启动 fscan ([Github](https://github.com/shadow1ng/fscan)) 扫描工具，并提供回显功能及超时强制终止功能。  
由于开发时限制，本工具仅限Windows平台使用。

### 基本使用

需要先安装Python，推荐使用 [Python 3.9](https://www.python.org/downloads/release/python-399/) 版本。  
然后执行以下命令安装依赖：
```shell
pip3 install wxPython
```
然后在项目根目录下执行以下命令启动主界面：
```shell
python GUI_fscan.py
```
（根目录下的fscan.exe为2022-01-01编译版本，架构为x64）
