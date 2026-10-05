#!/bin/sh
# bnat installer: downloads a release binary from GitHub and verifies its checksum.
#
#   curl -fsSL https://raw.githubusercontent.com/Suro4ek/bnat/main/install.sh | sh
#
# Environment:
#   BNAT_VERSION      release tag to install, e.g. v0.1.1 (default: latest)
#   BNAT_INSTALL_DIR  target directory (default: /usr/local/bin, or ~/.local/bin without sudo)
#   BNAT_REPO         GitHub repo to download from (default: Suro4ek/bnat)
#   BNAT_DOWNLOAD_BASE  releases URL override, for mirrors (default: https://github.com/$BNAT_REPO/releases)
#
# The whole script is wrapped in main() so a truncated download never runs half of it.

set -eu

main() {
	repo="${BNAT_REPO:-Suro4ek/bnat}"
	version="${BNAT_VERSION:-latest}"
	base="${BNAT_DOWNLOAD_BASE:-https://github.com/$repo/releases}"

	need uname
	need tar
	if has curl; then
		fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
		final_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
	elif has wget; then
		fetch() { wget -q -O "$2" "$1"; }
		final_url() { wget -q -S --spider "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
	else
		die "curl or wget is required"
	fi

	os=$(uname -s)
	case "$os" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	MINGW* | MSYS* | CYGWIN*) die "on Windows, download the .zip from $base/latest" ;;
	*) die "unsupported OS: $os" ;;
	esac

	arch=$(uname -m)
	case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture: $arch (prebuilt: amd64, arm64)" ;;
	esac
	# Rosetta reports x86_64 on Apple Silicon; prefer the native binary.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
		arch=arm64
	fi

	if [ "$version" = latest ]; then
		tag=$(final_url "$base/latest" | sed -n 's#.*/tag/##p')
		[ -n "$tag" ] || die "could not determine the latest release of $repo (no releases yet?)"
	else
		tag="v${version#v}"
	fi

	archive="bnat_${tag#v}_${os}_${arch}.tar.gz"
	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t bnat)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	say "downloading bnat $tag ($os/$arch)"
	fetch "$base/download/$tag/$archive" "$tmp/$archive" || die "download failed: $base/download/$tag/$archive"
	fetch "$base/download/$tag/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt"

	want=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
	[ -n "$want" ] || die "$archive is not listed in checksums.txt"
	got=$(sha256 "$tmp/$archive")
	[ "$want" = "$got" ] || die "checksum mismatch for $archive (expected $want, got $got)"

	tar -xzf "$tmp/$archive" -C "$tmp" bnat
	chmod +x "$tmp/bnat"

	dir="${BNAT_INSTALL_DIR:-/usr/local/bin}"
	if [ -n "${BNAT_INSTALL_DIR:-}" ]; then
		mkdir -p "$dir" 2>/dev/null || true
	fi
	if [ -d "$dir" ] && [ -w "$dir" ]; then
		mv -f "$tmp/bnat" "$dir/bnat"
	elif [ -z "${BNAT_INSTALL_DIR:-}" ] && has sudo && { sudo -n true 2>/dev/null || [ -t 2 ]; }; then
		say "installing to $dir (sudo)"
		sudo mkdir -p "$dir"
		sudo mv -f "$tmp/bnat" "$dir/bnat"
	elif [ -z "${BNAT_INSTALL_DIR:-}" ]; then
		dir="$HOME/.local/bin"
		mkdir -p "$dir"
		mv -f "$tmp/bnat" "$dir/bnat"
	else
		die "$dir is not writable"
	fi

	say "installed $("$dir/bnat" version) to $dir/bnat"
	case ":$PATH:" in
	*":$dir:"*) ;;
	*) say "note: $dir is not in PATH; add it:  export PATH=\"$dir:\$PATH\"" ;;
	esac
	cat <<EOF

Next steps:
  1. Admin panel → Clients → add a client, then run the command it shows:
       bnat login https://bnat.example.com XXXX-XXXX
  2. Expose something:
       bnat ssh -n myhost        # SSH with keys from the admin panel
       bnat http 3000 -n app     # https://app.<your bnat domain>
EOF
}

say() { printf 'bnat: %s\n' "$*" >&2; }
die() {
	say "error: $*"
	exit 1
}
has() { command -v "$1" >/dev/null 2>&1; }
need() { has "$1" || die "$1 is required"; }

sha256() {
	if has sha256sum; then
		sha256sum "$1" | awk '{ print $1 }'
	elif has shasum; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	elif has openssl; then
		openssl dgst -sha256 "$1" | awk '{ print $NF }'
	else
		die "no sha256 tool found (sha256sum, shasum or openssl)"
	fi
}

main "$@"
