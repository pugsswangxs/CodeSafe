# -*- coding: utf-8 -*-
# @Time : 2025-11-5 16:00
# @Author : wangxs1
# @Email : wxs15852445352@163.com
# @File : password_py.py
# @Software : PyCharm
# @Project : CodeSafe
# @bak :
# packager.py

# -*- coding: utf-8 -*-
# @Time : 2025-11-5 16:00
# @Author : wangxs1
# @Email : wxs15852445352@163.com
# @File : password_py.py
# @Software : PyCharm
# @Project : CodeSafe
# @bak :

import os
import sys
import platform
import argparse
from distutils.core import setup
from Cython.Build import cythonize


def pack_py_to_binary(py_file, output_dir=None, language_level=3, rename="Y"):
    """
    将Python文件打包为二进制文件(.so或.pyd)

    Args:
        py_file (str): 要打包的Python文件路径
        output_dir (str, optional): 输出目录，默认为源文件同级目录
        language_level (int): Python语言级别，默认为3
        :param rename: 是否给生成的pyd、so 文件重命名
    """
    # 检查文件是否存在
    if not os.path.exists(py_file):
        raise FileNotFoundError(f"文件不存在: {py_file}")
    # 确定输入文件所在文件夹
    py_dir = os.path.dirname(os.path.abspath(py_file))

    # 获取输入文件的所在的文件夹名称，只获取名称
    py_dir_name = os.path.basename(py_dir)

    # 确定输出目录
    if output_dir is None:
        output_dir = py_dir
    else:
        os.makedirs(output_dir, exist_ok=True)

    # 获取文件名（不含扩展名）
    if rename == "Y":
        file_name = os.path.splitext(os.path.basename(py_file))[0]
    else:
        file_name = None

    # 根据操作系统确定输出文件扩展名
    if platform.system() == "Windows":
        ext = ".pyd"
    else:
        ext = ".so"

    # .c文件也删除

    try:
        # 直接调用setup函数，不使用临时文件
        setup(
            name='file_name',
            ext_modules=cythonize(py_file, language_level=language_level),
            script_args=['build_ext', '--build-lib', output_dir]
        )
        if rename == "Y":
            # 获取生成文件的绝对路径
            for file_old in os.listdir(os.path.join(output_dir, py_dir_name)):
                if file_old.startswith(file_name) and (file_old.endswith(".pyd") or file_old.endswith(".so")):
                    # 重命名
                    os.replace(os.path.join(output_dir, py_dir_name, file_old),
                               os.path.join(output_dir, py_dir_name, file_name + ext))
    except Exception as e:
        print(f"打包失败: {str(e)}")
        sys.exit(0)
    except KeyboardInterrupt:
        print("用户中断")
    finally:
        # 清理build目录
        build_dir = os.path.join(output_dir, "build")
        if os.path.exists(build_dir):
            import shutil
            shutil.rmtree(build_dir, ignore_errors=True)
        _c = os.path.join(py_dir, file_name + ".c")
        if os.path.exists(_c):
            os.remove(_c)


def main():
    """主函数，处理命令行参数"""
    parser = argparse.ArgumentParser(description="将Python文件打包为二进制文件(.so或.pyd)")
    parser.add_argument("-p", "--py_file", help="要打包的Python文件路径")
    parser.add_argument("-o", "--output", help="输出目录，默认为源文件同级目录")
    parser.add_argument("-r", "--rename", type=str, default="Y", help="是否重命名该文件")
    parser.add_argument("-l", "--language-level", type=int, default=3,
                        help="Python语言级别 (默认: 3)")

    args = parser.parse_args()

    try:
        pack_py_to_binary(args.py_file, args.output, args.language_level, args.rename)
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
