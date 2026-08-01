#!/bin/bash

set -e

echo "============================================"
echo "  CTF AI Agent - 第三方工具安装脚本"
echo "============================================"
echo ""

THIRDPARTY_DIR="src/thirdparty"

mkdir -p "$THIRDPARTY_DIR"

echo "[1/4] 正在安装 sqlmap..."
if [ -d "$THIRDPARTY_DIR/sqlmap" ]; then
    echo "  sqlmap 已存在，跳过"
else
    git clone https://github.com/sqlmapproject/sqlmap.git "$THIRDPARTY_DIR/sqlmap"
    echo "  sqlmap 安装完成"
fi

echo ""
echo "[2/4] 正在安装 Fenjing (分筋)..."
if [ -d "$THIRDPARTY_DIR/Fenjing" ]; then
    echo "  Fenjing 已存在，跳过"
else
    git clone https://github.com/duo-labs/fenjing.git "$THIRDPARTY_DIR/Fenjing"
    pip install -e "$THIRDPARTY_DIR/Fenjing" 2>/dev/null || pip install -q "$THIRDPARTY_DIR/Fenjing"
    echo "  Fenjing 安装完成"
fi

echo ""
echo "[3/4] 正在安装 flask-session-cookie-manager..."
if [ -d "$THIRDPARTY_DIR/flask-session-cookie-manager-master" ]; then
    echo "  flask-session-cookie-manager 已存在，跳过"
else
    curl -L -o /tmp/flask-session-cookie-manager.zip https://github.com/noraj/flask-session-cookie-manager/archive/refs/heads/master.zip
    unzip -q /tmp/flask-session-cookie-manager.zip -d "$THIRDPARTY_DIR"
    rm /tmp/flask-session-cookie-manager.zip
    echo "  flask-session-cookie-manager 安装完成"
fi

echo ""
echo "[4/4] 正在下载 ysoserial..."
mkdir -p "$THIRDPARTY_DIR/ysoserial"
if [ -f "$THIRDPARTY_DIR/ysoserial/ysoserial-all.jar" ]; then
    echo "  ysoserial 已存在，跳过"
else
    curl -L -o "$THIRDPARTY_DIR/ysoserial/ysoserial-all.jar" https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
    echo "  ysoserial 下载完成"
fi

echo ""
echo "============================================"
echo "  所有第三方工具安装完成！"
echo "============================================"
echo ""
echo "接下来请："
echo "1. 复制 .env.example 为 .env"
echo "2. 在 .env 中填入您的 DeepSeek API Key"
echo "3. 运行: python src/main.py"
echo ""
echo "工具路径："
echo "  sqlmap:        $THIRDPARTY_DIR/sqlmap/sqlmap.py"
echo "  Fenjing:       $THIRDPARTY_DIR/Fenjing/"
echo "  ysoserial:     $THIRDPARTY_DIR/ysoserial/ysoserial-all.jar"
echo "  flask-session: $THIRDPARTY_DIR/flask-session-cookie-manager-master/"
