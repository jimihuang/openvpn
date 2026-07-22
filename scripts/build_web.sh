#!/usr/bin/env bash
# 构建新版 Vue SPA 并复制到 Go 后端的 embed 目录,再编译 openvpn-web 二进制。
# 旧版内置 jQuery/Bootstrap 界面已下线,此脚本产出的 SPA 是唯一的 Web UI。
#
# 用法: ./scripts/build_web.sh [目标平台,如 linux/amd64、linux/arm64;默认本机平台]

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
WEB_DIR="$ROOT/web"
GO_DIR="$ROOT/src/openvpn-web"
EMBED_DIR="$GO_DIR/webdist"

command -v bun >/dev/null 2>&1 || { echo "错误: 需要 bun,请先安装 https://bun.sh" >&2; exit 1; }
command -v go  >/dev/null 2>&1 || { echo "错误: 需要 go 工具链" >&2; exit 1; }

echo "==> 安装前端依赖并构建"
cd "$WEB_DIR"
bun install --frozen-lockfile
bun run build

echo "==> 复制构建产物到 ${EMBED_DIR}"
rm -rf "$EMBED_DIR"
mkdir -p "$EMBED_DIR"
cp -r "$WEB_DIR/dist/." "$EMBED_DIR/"

echo "==> 编译 openvpn-web"
cd "$GO_DIR"
TARGET="${1:-}"
if [ -n "$TARGET" ]; then
    GOOS="${TARGET%/*}"
    GOARCH="${TARGET#*/}"
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -o "$ROOT/build/openvpn-web-${GOOS}-${GOARCH}" .
    echo "输出: build/openvpn-web-${GOOS}-${GOARCH}"
else
    CGO_ENABLED=0 go build -o "$ROOT/build/openvpn-web" .
    echo "输出: build/openvpn-web"
fi
