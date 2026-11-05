#!/bin/sh
# Собирает zip для пользователей Windows из уже собранного release-exe.
#   tools/package-windows.sh MIHOMO_EXE MMDB OUT.zip
# MIHOMO_EXE — официальная сборка mihomo-windows-amd64-compatible (GOAMD64=v1).
set -eu
[ $# -eq 3 ] || { echo "usage: $0 MIHOMO_EXE MMDB OUT.zip" >&2; exit 2; }
MIHOMO=$1 MMDB=$2 OUT=$3
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TARGET=x86_64-pc-windows-gnullvm
EXE=$ROOT/target/$TARGET/release/lazeyka.exe
[ -f "$EXE" ] || { echo "нет $EXE — сначала cargo build --release --target $TARGET" >&2; exit 1; }
[ ! -e "$OUT" ] || { echo "$OUT уже существует — укажите другое имя" >&2; exit 1; }
if strings -n 6 "$MIHOMO" | grep -q "GOAMD64=v[234]"; then
    echo "внимание: $MIHOMO собран не для GOAMD64=v1 (нужна сборка compatible)" >&2
fi
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
D=$STAGE/Lazeyka
mkdir -p "$D"
cp "$EXE" "$D/lazeyka.exe"
cp "$MIHOMO" "$D/mihomo.exe"
cp "$MMDB" "$D/dbip-country-lite.mmdb"
# тексты: CRLF, README и THIRD-PARTY — UTF-8 с BOM (для старых версий Блокнота)
sed 's/$/\r/' "$ROOT/LICENSE" > "$D/LICENSE.txt"
{ printf '\357\273\277'; sed 's/$/\r/' "$ROOT/dist/README.txt"; } > "$D/README.txt"
python3 "$ROOT/tools/gen-third-party.py" "$TARGET" "$D/THIRD-PARTY.txt"
OUT_ABS=$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")
(cd "$STAGE" && zip -q -X -9 -r "$OUT_ABS" Lazeyka)
ls -l "$OUT_ABS"
(cd "$D" && sha256sum lazeyka.exe mihomo.exe dbip-country-lite.mmdb)
sha256sum "$OUT_ABS"
