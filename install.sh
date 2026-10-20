#!/bin/sh
# Installs or updates Agentchat under ~/.agentchat from this unpacked package (macOS or Linux), then joins with the invite and flags passed in.
# The pasted line verifies the package's SHA-256 before this runs; this script pins Node the same way, then hands over to the package's own install step.
set -eu

NODE_VERSION=24.22.0
NODE_SHA256_DARWIN_ARM64=75ddfb875bbd868ebe57536f4442225f54dd10f6d2178dd439de869a5c648dc3
NODE_SHA256_DARWIN_X64=b890d687983ddc811641f6739c3ce99d2912c58f9e44b68aa25944037b425305
NODE_SHA256_LINUX_ARM64=b7e7991d5407815adfa74a2a9cd4db683552c8ce32ff4a295c22e972849c3f5d
NODE_SHA256_LINUX_X64=28ea0a438de9a13bd7891fd758eee6c7819ee8af5442dfd8d45bd65e56d4228c

die() { printf 'agentchat: %s\n' "$*" >&2; exit 1; }
at_least() { awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, "."); split(b, y, "."); for (i = 1; i <= 3; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 } exit 0 }'; }
# macOS's own sha256sum can't read a checklist from stdin without "-", and a Linux box may lack Perl's shasum.
check_sha256() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 -c - >/dev/null; else sha256sum -c - >/dev/null; fi; }

case "$(uname -s)" in
  Darwin)
    [ "$(id -u)" != 0 ] || die "Run this as yourself, not with sudo."
    os=$(sw_vers -productVersion)
    at_least "$os" 13.5 || die "Agentchat needs macOS 13.5 or newer; this Mac has $os."
    # Apple Silicon reports hw.optional.arm64=1 even from a Rosetta shell; Intel Macs don't have the key at all.
    if [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then arch=arm64 node_sha=$NODE_SHA256_DARWIN_ARM64; else arch=x64 node_sha=$NODE_SHA256_DARWIN_X64; fi
    archive=node-v$NODE_VERSION-darwin-$arch.tar.xz node_name=v$NODE_VERSION-$arch ;;
  Linux)
    # Root is fine on a server or in a container, but sudo from a user would leave root-owned files in that user's home.
    if [ "$(id -u)" = 0 ] && [ "$(stat -c %u "$HOME" 2>/dev/null || echo 0)" != 0 ]; then die "Run this as the user who will use Agentchat, not with sudo."; fi
    case "$(uname -m)" in
      x86_64 | amd64) arch=x64 node_sha=$NODE_SHA256_LINUX_X64 ;;
      aarch64 | arm64) arch=arm64 node_sha=$NODE_SHA256_LINUX_ARM64 ;;
      *) die "Agentchat runs on 64-bit Intel/AMD or ARM Linux; this machine is $(uname -m)." ;;
    esac
    glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | sed -n 's/^glibc //p' || true)
    [ -n "$glibc" ] || die "Agentchat needs a glibc-based Linux such as Debian, Ubuntu, Fedora or Amazon Linux 2023; Alpine and other musl systems aren't supported."
    at_least "$glibc" 2.28 || die "Agentchat needs glibc 2.28 or newer (Debian 10, Ubuntu 18.10, Amazon Linux 2023 or later); this machine has glibc $glibc."
    archive=node-v$NODE_VERSION-linux-$arch.tar.gz node_name=v$NODE_VERSION-linux-$arch ;;
  *) die "On Windows, paste the PowerShell line from your invite instead." ;;
esac

here=$(cd "$(dirname "$0")" && pwd -P)
root=$HOME/.agentchat
node_dir=$root/node/$node_name

if [ ! -x "$node_dir/bin/node" ]; then
  printf 'Downloading Node %s for this computer...\n' "$NODE_VERSION"
  tmp=$root/node/.tmp-$$
  rm -rf "$tmp"
  mkdir -p "$tmp"
  curl -f#SL "https://nodejs.org/dist/v$NODE_VERSION/$archive" -o "$tmp/$archive"
  echo "$node_sha  $tmp/$archive" | check_sha256 || die "The Node download didn't match its pinned SHA-256, so nothing was installed. Paste the same line again."
  dir=${archive%.tar.*}
  tar -xf "$tmp/$archive" -C "$tmp" "$dir/bin/node" "$dir/LICENSE"
  "$tmp/$dir/bin/node" -v >/dev/null 2>&1 || die "This computer can't run Node $NODE_VERSION."
  rm -rf "$node_dir"
  mv "$tmp/$dir" "$node_dir"
  rm -rf "$tmp"
fi

exec "$node_dir/bin/node" "$here/bin/agentchat.js" install "$@"
