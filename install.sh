#!/bin/sh
# bnat installer and updater: downloads a release binary from GitHub, verifies
# its checksum, and replaces an existing install in place (restarting services).
#
#   curl -fsSL https://raw.githubusercontent.com/Suro4ek/bnat/main/install.sh | sh
#
# Environment:
#   BNAT_VERSION      release tag to install, e.g. v0.1.1 (default: latest)
#   BNAT_INSTALL_DIR  target directory (default: where bnat already is, else /usr/local/bin,
#                     or ~/.local/bin without sudo)
#   BNAT_FORCE=1      reinstall even if this version is already installed
#   BNAT_REPO         GitHub repo to download from (default: Suro4ek/bnat)
#   BNAT_DOWNLOAD_BASE  where releases are downloaded from (default: GitHub)
#   BNAT_FALLBACK_BASE  used when that is unreachable (default: the release.bnat.ctai.dev
#                       mirror; set to "" to disable)
#
# The whole script is wrapped in main() so a truncated download never runs half of it.

set -eu

main() {
	repo="${BNAT_REPO:-Suro4ek/bnat}"
	version="${BNAT_VERSION:-latest}"
	# The bnat server's release mirror rewrites these two lines when serving this script.
	primary="${BNAT_DOWNLOAD_BASE:-https://github.com/$repo/releases}" # bnat:primary
	fallback="${BNAT_FALLBACK_BASE-https://release.bnat.ctai.dev}" # bnat:fallback
	base="$primary"

	need uname
	need tar
	if has curl; then
		# Give up on hosts that hang or crawl (blocked/throttled GitHub) instead of waiting forever.
		fetch() { curl -fsSL --retry 2 --connect-timeout 10 --speed-limit 2048 --speed-time 20 -o "$2" "$1"; }
		final_url() { curl -fsSLI --connect-timeout 10 -m 30 -o /dev/null -w '%{url_effective}' "$1"; }
	elif has wget; then
		fetch() { wget -q -T 20 -O "$2" "$1"; }
		final_url() { wget -q -T 20 -S --spider "$1" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
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
		tag=$(latest_tag "$base")
		if [ -z "$tag" ] && use_fallback; then
			tag=$(latest_tag "$base")
		fi
		[ -n "$tag" ] || die "could not determine the latest release (no releases yet, or $base unreachable)"
	else
		tag="v${version#v}"
	fi

	# An existing install is updated in place, so services keep using the same path.
	existing=""
	if [ -n "${BNAT_INSTALL_DIR:-}" ]; then
		[ -x "$BNAT_INSTALL_DIR/bnat" ] && existing="$BNAT_INSTALL_DIR/bnat"
	else
		existing=$(command -v bnat 2>/dev/null || true)
	fi
	current=""
	if [ -n "$existing" ]; then
		current=$("$existing" version 2>/dev/null | awk '{ print $2 }' || true)
		if [ "$current" = "${tag#v}" ] && [ "${BNAT_FORCE:-}" != 1 ]; then
			say "bnat $current is already up to date ($existing)"
			return 0
		fi
	fi

	archive="bnat_${tag#v}_${os}_${arch}.tar.gz"
	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t bnat)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	if [ -n "$existing" ]; then
		say "updating bnat ${current:-?} -> ${tag#v} ($os/$arch)"
	else
		say "downloading bnat $tag ($os/$arch)"
	fi
	if ! fetch "$base/download/$tag/$archive" "$tmp/$archive"; then
		use_fallback || die "download failed: $base/download/$tag/$archive"
		fetch "$base/download/$tag/$archive" "$tmp/$archive" || die "download failed: $base/download/$tag/$archive"
	fi
	fetch "$base/download/$tag/checksums.txt" "$tmp/checksums.txt" || die "could not download checksums.txt from $base"

	want=$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")
	[ -n "$want" ] || die "$archive is not listed in checksums.txt"
	got=$(sha256 "$tmp/$archive")
	[ "$want" = "$got" ] || die "checksum mismatch for $archive (expected $want, got $got)"

	tar -xzf "$tmp/$archive" -C "$tmp" bnat
	chmod 755 "$tmp/bnat"

	if [ -n "${BNAT_INSTALL_DIR:-}" ]; then
		dir="$BNAT_INSTALL_DIR"
	elif [ -n "$existing" ]; then
		dir=$(dirname "$existing")
	else
		dir=/usr/local/bin
	fi
	mkdir -p "$dir" 2>/dev/null || true
	if [ -d "$dir" ] && [ -w "$dir" ]; then
		SUDO=""
	elif [ "$(id -u)" != 0 ] && can_sudo; then
		SUDO=sudo
		say "installing to $dir (sudo)"
	elif [ -z "${BNAT_INSTALL_DIR:-}" ] && [ -z "$existing" ]; then
		dir="$HOME/.local/bin"
		SUDO=""
	else
		die "$dir is not writable (run as root or set BNAT_INSTALL_DIR)"
	fi

	# Copy next to the target, then rename: atomic, and safe while bnat is running.
	$SUDO mkdir -p "$dir"
	$SUDO cp "$tmp/bnat" "$dir/.bnat.new.$$"
	$SUDO chmod 755 "$dir/.bnat.new.$$"
	$SUDO mv -f "$dir/.bnat.new.$$" "$dir/bnat"

	installed=$("$dir/bnat" version)
	if [ -n "$existing" ]; then
		say "updated to $installed ($dir/bnat)"
		restart_services "$dir/bnat"
		return 0
	fi

	say "installed $installed to $dir/bnat"
	case ":$PATH:" in
	*":$dir:"*) ;;
	*) say "note: $dir is not in PATH; add it:  export PATH=\"$dir:\$PATH\"" ;;
	esac
	cat <<EOF

Next steps:
  1. Admin panel -> Clients -> add a client, then run the command it shows:
       bnat login https://bnat.example.com XXXX-XXXX
  2. Expose something:
       bnat ssh -n myhost        # SSH with keys from the admin panel
       bnat http 3000 -n app     # https://app.<your bnat domain>
  3. Keep it running in the background and after reboots:
       sudo bnat service install ssh -n myhost

Update later by re-running this script or with: bnat update
EOF
}

# restart_services restarts bnat services so they pick up the new binary:
# per-user ones as the current user, system ones as root.
restart_services() {
	bin=$1
	if [ "$(id -u)" != 0 ]; then
		"$bin" service restart --all --quiet 2>/dev/null || true
	fi
	system_services=""
	for f in /etc/systemd/system/bnat-*.service /Library/LaunchDaemons/com.github.suro4ek.bnat.*.plist; do
		[ -e "$f" ] && system_services=1
	done
	if [ -n "$system_services" ]; then
		if [ "$(id -u)" = 0 ]; then
			"$bin" service restart --all --quiet || say "warning: some services failed to restart"
		elif can_sudo; then
			say "restarting bnat system services (sudo)"
			sudo "$bin" service restart --all --quiet || say "warning: some services failed to restart"
		else
			say "restart system services to use the new version: sudo bnat service restart --all"
		fi
	fi
}

latest_tag() { final_url "$1/latest" 2>/dev/null | sed -n 's#.*/tag/##p'; }

# use_fallback switches downloads to the fallback mirror, if there is one left to try.
use_fallback() {
	[ -n "$fallback" ] && [ "$base" != "$fallback" ] || return 1
	say "$base is unreachable, using mirror $fallback"
	base="$fallback"
}

# can_sudo: sudo works without a password, or we can prompt on the terminal.
can_sudo() { has sudo && { sudo -n true 2>/dev/null || [ -t 2 ]; }; }

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
