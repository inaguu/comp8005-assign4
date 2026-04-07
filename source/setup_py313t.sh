#!/usr/bin/env bash
set -e

PY_VERSION=3.13.0
PREFIX="$PWD/.python313t"
VENV_DIR="$PWD/.venv"

echo "📦 Installing dependencies (requires sudo)..."
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev \
libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev \
libgdbm-dev libbz2-dev libffi-dev liblzma-dev tk-dev uuid-dev wget

echo "⬇️ Downloading Python $PY_VERSION..."
cd /tmp
wget -q https://www.python.org/ftp/python/$PY_VERSION/Python-$PY_VERSION.tgz
tar -xf Python-$PY_VERSION.tgz
cd Python-$PY_VERSION

echo "⚙️ Configuring (GIL-free build)..."
./configure --prefix="$PREFIX" --disable-gil --enable-optimizations

echo "🔨 Building..."
make -j$(nproc)

echo "📥 Installing locally to $PREFIX..."
make install

echo "🐍 Creating virtual environment..."
"$PREFIX/bin/python3.13" -m venv "$VENV_DIR"

echo "✅ Done!"
echo ""
echo "Activate with:"
echo "source .venv/bin/activate"

echo ""
echo "Test GIL status:"
echo "python -c 'import sys; print(sys._is_gil_enabled())'"
