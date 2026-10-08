filepath=$1
filename=$(basename $filepath)
fileext=${filename#*.}

# ANSI colors (uniform across helpers)
RED='\033[1;31m'
GRN='\033[1;32m'
YEL='\033[1;33m'
BLU='\033[1;34m'
MAG='\033[1;35m'
CYN='\033[1;36m'
DIM='\033[2m'
RST='\033[0m'

# Nerdy universal purge: secure, colorized, root-aware artifact deletion
# Usage:
#   fs_quantum_purge [--dir PATH] [--glob PATTERN ...] [--yes|-y] [--dry-run]
#                    [--allow-any-dir]
# Defaults:
#   --dir resolves to .../rust_backend/scans (env NETSCAN_SCANS_DIR or auto-detect)
#   --glob defaults to 'scan-*.csv' and 'scan-*.json'
# Notes:
#   - Non-root: prompts if any file is not writable (likely root-owned).
#   - Safe by default: refuses non-standard paths unless --allow-any-dir.
fs_quantum_purge() {
  local dir="" force=0 dry=0 allow_any=0
  local globs=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --dir|--scans-dir) dir="$2"; shift 2 ;;
      --glob) globs+=("$2"); shift 2 ;;
      --yes|-y) force=1; shift ;;
      --dry-run) dry=1; shift ;;
      --allow-any-dir) allow_any=1; shift ;;
      --help|-h)
        echo -e "${BLU}fs_quantum_purge${RST} ${DIM}- secure artifact purge (root-aware)${RST}"
        echo -e "  ${CYN}--dir PATH${RST}           Target directory"
        echo -e "  ${CYN}--glob PATTERN${RST}       One or more filename patterns (repeatable)"
        echo -e "  ${CYN}--yes | -y${RST}           Skip confirmation"
        echo -e "  ${CYN}--dry-run${RST}            Print actions only"
        echo -e "  ${CYN}--allow-any-dir${RST}      Disable path safety check"
        echo -e "  ${DIM}Env:${RST} NETSCAN_SCANS_DIR=/abs/path/to/rust_backend/scans"
        return 0
        ;;
      *) echo -e "${YEL}Unknown arg${RST}: $1"; return 2 ;;
    esac
  done

  # Resolve directory if not provided
  if [[ -z "$dir" && -n "${NETSCAN_SCANS_DIR:-}" ]]; then
    dir="$NETSCAN_SCANS_DIR"
  fi
  if [[ -z "$dir" && -d "./scans" && "$(basename "$(pwd)")" == "rust_backend" ]]; then
    dir="$(pwd)/scans"
  fi
  if [[ -z "$dir" && -d "./rust_backend/scans" ]]; then
    dir="$(pwd)/rust_backend/scans"
  fi
  if [[ -z "$dir" ]]; then
    local git_root
    git_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -n "$git_root" && -d "$git_root/rust_backend/scans" ]]; then
      dir="$git_root/rust_backend/scans"
    fi
  fi
  if [[ -z "$dir" && -d "$HOME/private/projects/desktop/java/netscan/rust_backend/scans" ]]; then
    dir="$HOME/private/projects/desktop/java/netscan/rust_backend/scans"
  fi
  if [[ -z "$dir" || ! -d "$dir" ]]; then
    echo -e "${RED}[fatal]${RST} scans directory not found."
    echo -e "  ${CYN}Hint${RST}: pass ${YEL}--dir PATH${RST} or set ${YEL}NETSCAN_SCANS_DIR${RST}"
    return 3
  fi

  # Normalize path
  dir="$(readlink -f -- "$dir" 2>/dev/null || realpath -- "$dir" 2>/dev/null || echo "$dir")"

  # Path guard unless explicitly allowed
  if (( ! allow_any )) && [[ "$dir" != *"/rust_backend/scans" ]]; then
    echo -e "${YEL}[safe-guard]${RST} refusing non-standard path:"
    echo -e "  ${DIM}$dir${RST}"
    echo -e "  ${CYN}Use${RST} ${YEL}--allow-any-dir${RST} to override (dangerous)."
    return 4
  fi
  if [[ "$dir" == "/" || "$dir" == "/root" || "$dir" == "/home" ]]; then
    echo -e "${RED}[fatal]${RST} dangerous path: ${DIM}$dir${RST}"
    return 5
  fi

  # Default globs (netscan artifacts)
  if (( ${#globs[@]} == 0 )); then
    globs=( "scan-*.csv" "scan-*.json" )
  fi

  # Heading
  echo -e "${BLU}=== FS QUANTUM PURGE ===${RST}"
  echo -e "${CYN}Dir:${RST} ${DIM}$dir${RST}"
  echo -e "${CYN}Patterns:${RST} ${DIM}${globs[*]}${RST}\n"

  # Collect candidate files
  local find_expr=()
  for g in "${globs[@]}"; do
    if (( ${#find_expr[@]} > 0 )); then find_expr+=( -o ); fi
    find_expr+=( -name "$g" )
  done

  local files
  if ! files="$(find "$dir" -maxdepth 1 -type f \( "${find_expr[@]}" \) -print)"; then
    echo -e "${RED}[fatal]${RST} failed to list files in ${DIM}$dir${RST}"
    return 6
  fi
  if [[ -z "$files" ]]; then
    echo -e "${YEL}[noop]${RST} no matching artifacts found."
    return 0
  fi

  local count
  count=$(printf "%s\n" "$files" | wc -l | awk '{print $1}')
  echo -e "${GRN}[found]${RST} ${DIM}$count file(s)${RST}"
  printf "  ${DIM}%s${RST}\n" $files
  echo

  # Root-awareness: check writability if not root
  local need_root=0
  if [[ $EUID -ne 0 ]]; then
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      if [[ ! -w "$f" || ! -w "$dir" ]]; then
        need_root=1; break
      fi
    done <<< "$files"

    if (( need_root )); then
      echo -e "${YEL}[privilege]${RST} some files appear ${DIM}root-owned or not writable${RST}."
      echo -e "  ${CYN}Recommended:${RST} re-run with ${YEL}sudo${RST}."
      read -r -p "$(echo -e "${YEL}Proceed without sudo (may fail)?${RST} [y/N]: ")" ans
      case "$ans" in
        y|Y|yes|YES) : ;;
        *) echo -e "${RED}Aborted.${RST}"; return 0 ;;
      esac
    fi
  fi

  if (( dry )); then
    echo -e "${CYN}[dry-run]${RST} would securely delete the files above."
    return 0
  fi

  if (( ! force )); then
    read -r -p "$(echo -e "${YEL}Permanently delete${RST} ${DIM}$count${RST} file(s)? [y/N]: ")" ans
    case "$ans" in
      y|Y|yes|YES) : ;;
      *) echo -e "${RED}Aborted.${RST}"; return 0 ;;
    esac
  fi

  # Perform purge
  local ok=0 fail=0
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if command -v shred >/dev/null 2>&1; then
      if shred -uzn 0 -- "$f" 2>/dev/null; then
        ((ok++))
      else
        rm -f -- "$f" && ((ok++)) || ((fail++))
      fi
    else
      rm -f -- "$f" && ((ok++)) || ((fail++))
    fi
  done <<< "$files"

  if (( fail == 0 )); then
    echo -e "${GRN}[ok]${RST} deleted: ${DIM}$ok${RST}"
    return 0
  else
    echo -e "${RED}[partial]${RST} deleted: ${DIM}$ok${RST}  failed: ${DIM}$fail${RST}"
    return 7
  fi
}

# Backward-compatible alias
clean_netscan_scans() {
  fs_quantum_purge "$@"
}

# Allow running directly:
#   ./utils.sh fs-quantum-purge [args...]
#   ./utils.sh clean-netscan-scans [args...]
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    fs-quantum-purge) shift; fs_quantum_purge "$@";;
    clean-netscan-scans) shift; fs_quantum_purge "$@";;
    *)
      # ...existing code or print brief help...
      ;;
  esac
fi
