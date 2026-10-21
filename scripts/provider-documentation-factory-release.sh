#!/bin/sh
set -eu
umask 077

fail() {
  printf '%s\n' 'provider-documentation-factory-release bootstrap: failed' >&2
  exit 1
}

[ "$#" -ge 5 ] || fail
source_root=$1
commit=$2
go_executable=$3
git_executable=$4
[ "$5" = "--" ] || fail
shift 5

case "$commit" in
  *[!0-9a-f]*|'') fail ;;
esac
[ "${#commit}" -eq 40 ] || fail
case "$source_root" in /*) ;; *) fail ;; esac
case "$go_executable" in /*) ;; *) fail ;; esac
case "$git_executable" in /*) ;; *) fail ;; esac
[ -d "$source_root" ] || fail
[ -f "$go_executable" ] && [ -x "$go_executable" ] || fail
[ -f "$git_executable" ] && [ -x "$git_executable" ] || fail

select_bootstrap_utility() {
  for candidate in "$@"; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

mkdir_utility=$(select_bootstrap_utility /bin/mkdir /usr/bin/mkdir) || fail
rm_utility=$(select_bootstrap_utility /bin/rm /usr/bin/rm) || fail
env_utility=$(select_bootstrap_utility /usr/bin/env /bin/env) || fail

physical_tmp=$(CDPATH= cd /tmp && pwd -P) || fail
case "$physical_tmp" in /*) ;; *) fail ;; esac
[ -d "$physical_tmp" ] || fail

bootstrap_root=
bootstrap_counter=0
while [ "$bootstrap_counter" -lt 100 ]; do
  candidate_root="$physical_tmp/velenza-provider-factory-bootstrap.$$.$bootstrap_counter"
  if "$mkdir_utility" -m 700 -- "$candidate_root" 2>/dev/null; then
    bootstrap_root=$candidate_root
    break
  fi
  bootstrap_counter=$((bootstrap_counter + 1))
done
[ -n "$bootstrap_root" ] || fail
cleanup() {
	cleanup_status=$?
	trap - EXIT HUP INT TERM
  case "$bootstrap_root" in
    "$physical_tmp"/velenza-provider-factory-bootstrap.*) "$rm_utility" -rf -- "$bootstrap_root" || : ;;
  esac
	exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$mkdir_utility" -m 700 "$bootstrap_root/home" "$bootstrap_root/cache" "$bootstrap_root/modcache" \
  "$bootstrap_root/gopath" "$bootstrap_root/gotmp" "$bootstrap_root/tmp" "$bootstrap_root/config" \
  "$bootstrap_root/bin" || fail
: >"$bootstrap_root/config/gitconfig"
launcher="$bootstrap_root/provider-documentation-factory-release.go"
platform_launcher="$bootstrap_root/child_process_nonwindows.go"
receipt_publisher="$bootstrap_root/receipt_publish_nonwindows.go"
closed_path=$bootstrap_root/bin

git_env() {
  "$env_utility" -i \
    HOME="$bootstrap_root/home" \
    PATH="$closed_path" \
    LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL="$bootstrap_root/config/gitconfig" \
    GIT_NO_REPLACE_OBJECTS=1 \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= GCM_INTERACTIVE=never \
    "$git_executable" "$@"
}

[ -z "$(git_env -C "$source_root" for-each-ref --format='%(refname)' refs/replace)" ] || fail
git_env -C "$source_root" cat-file -e "$commit^{commit}" || fail
[ "$(git_env -C "$source_root" rev-parse --verify "$commit^{commit}")" = "$commit" ] || fail
git_env -C "$source_root" show "$commit:cmd/provider-documentation-factory-release/main.go" >"$launcher" || fail
git_env -C "$source_root" show "$commit:cmd/provider-documentation-factory-release/child_process_nonwindows.go" >"$platform_launcher" || fail
git_env -C "$source_root" show "$commit:cmd/provider-documentation-factory-release/receipt_publish_nonwindows.go" >"$receipt_publisher" || fail
[ -s "$launcher" ] && [ -s "$platform_launcher" ] && [ -s "$receipt_publisher" ] || fail

"$env_utility" -i \
  HOME="$bootstrap_root/home" USERPROFILE="$bootstrap_root/home" \
  PATH="$closed_path" \
  LANG=C LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0 \
  TMP="$bootstrap_root/tmp" TEMP="$bootstrap_root/tmp" TMPDIR="$bootstrap_root/tmp" \
  XDG_CACHE_HOME="$bootstrap_root/cache" XDG_CONFIG_HOME="$bootstrap_root/config" \
  CGO_ENABLED=0 GO_EXTLINK_ENABLED=0 GO111MODULE=off GOENV=off GOWORK=off \
  GOTOOLCHAIN=local GOFLAGS= GOCACHE="$bootstrap_root/cache" \
  GOMODCACHE="$bootstrap_root/modcache" GOPATH="$bootstrap_root/gopath" GOTMPDIR="$bootstrap_root/gotmp" \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL="$bootstrap_root/config/gitconfig" \
  GIT_NO_REPLACE_OBJECTS=1 \
  GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= GCM_INTERACTIVE=never \
  "$go_executable" run -trimpath "$launcher" "$platform_launcher" "$receipt_publisher" \
    --source-root "$source_root" --commit "$commit" \
    --go-executable "$go_executable" --git-executable "$git_executable" -- "$@"
