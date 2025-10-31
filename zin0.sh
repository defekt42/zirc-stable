#!/bin/sh
# zin0.sh — Minimalist, High-Security tmux input helper (use with zirc v2.5)

PANE="zirc:0.0"
PROMPT="zirc> "
ZCONF="${HOME}/.config/zirc"
NICKS_FILE="${ZCONF}/nicklist.txt"
BLACKLIST_FILE="${ZCONF}/blacklist.txt"
HIST_FILE="${ZCONF}/.zirc_history"
NICK_UPDATE_INTERVAL=8

# --- Dependency Check ---
for cmd in rlwrap tmux; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: $cmd not found. Install with your package manager." >&2
        exit 1
    fi
done

# --- Initialization ---
mkdir -p "$ZCONF" && chmod 700 "$ZCONF"
touch "$NICKS_FILE" "$HIST_FILE"
chmod 600 "$NICKS_FILE" "$HIST_FILE"

# Create default blacklist if missing
if [ ! -f "$BLACKLIST_FILE" ]; then
    cat > "$BLACKLIST_FILE" <<'EOF'
# Example Blacklist - one entry per line
^[0-9]+$
^($
^password$
^Password$
^prompt$
^someNick$
EOF
    chmod 600 "$BLACKLIST_FILE"
fi

# --- Function: watch_nicks ---
watch_nicks() {
    local temp_file="${NICKS_FILE}.$$"
    local blacklist_patterns="${temp_file}.bl"

    # 1. Extract nicks from chat
    tmux capture-pane -t "$PANE" -p -S -1000 2>/dev/null |
        grep -o '<[^>]*>' | sed 's/[<>]//g' | grep -v '^$' > "$temp_file"

    [ -s "$temp_file" ] || { rm -f "$temp_file" 2>/dev/null; return 0; }

    # 2. Filter blacklisted nicks
    if [ -f "$BLACKLIST_FILE" ]; then
        grep -v '^#' "$BLACKLIST_FILE" | tr -d '\r' |
        sed 's/^[ \t]*//g' | grep -v '^$' > "$blacklist_patterns"

        if [ -s "$blacklist_patterns" ]; then
            grep -v -F -f "$blacklist_patterns" "$temp_file" > "${temp_file}.filtered"
            [ -s "${temp_file}.filtered" ] && mv "${temp_file}.filtered" "$temp_file"
        fi
        rm -f "$blacklist_patterns"
    fi

    # 3. Merge with existing nicks safely
    if [ -f "$NICKS_FILE" ]; then
        cat "$NICKS_FILE" "$temp_file" 2>/dev/null | sort -u > "${temp_file}.merged"
        [ -s "${temp_file}.merged" ] && mv "${temp_file}.merged" "$temp_file"
    fi

    # 4. Atomic update of nicklist
    if [ -s "$temp_file" ] && [ -n "$NICKS_FILE" ]; then
        chmod 600 "$temp_file"
        tmp_target="${NICKS_FILE}.tmp"
        cp "$temp_file" "$tmp_target" && mv "$tmp_target" "$NICKS_FILE"
    fi

    # 5. Cleanup temp files
    rm -f "$temp_file" 2>/dev/null
}

# --- Cleanup ---
cleanup() {
    [ -n "$WATCHER_PID" ] && kill "$WATCHER_PID" 2>/dev/null
    rm -f "${NICKS_FILE}".* 2>/dev/null
    exit 0
}
trap cleanup INT TERM EXIT

# --- Background Nick Watcher ---
while :; do
    sleep "$NICK_UPDATE_INTERVAL"
    watch_nicks
done &
WATCHER_PID=$!

# --- Main rlwrap Loop with auto-reload ---
while :; do
    rlwrap -R -H "$HIST_FILE" -D2 -S "$PROMPT" -b '' -f "$NICKS_FILE" sh -c '
PANE="'"$PANE"'"
trap "" HUP

while :; do
    # Read input from rlwrap
    if ! IFS= read -r line; then
        break
    fi
    [ -z "$line" ] && continue

    case "$line" in
        /quit|:quit)
            tmux send-keys -t "$PANE" "/quit" Enter 2>/dev/null
            echo "[zirc] IRC client quitting..."
            break
            ;;
        :reload)
            echo "[zirc] Manual reload triggered..."
            '"$(typeset -f watch_nicks)"'
            watch_nicks
            # touch file to update timestamp so rlwrap notices changes
            touch "'"$NICKS_FILE"'"
            echo "[zirc] Nicklist and blacklist reloaded."
            continue
            ;;
        *)
            tmux send-keys -t "$PANE" "$line" Enter 2>/dev/null
            ;;
    esac

    # --- Soft auto-reload ---
    # Update timestamp to hint rlwrap to reload completions
    touch "'"$NICKS_FILE"'"
done
'
rc=$?

if [ $rc -eq 0 ]; then
    echo "[zirc] rlwrap exited cleanly."
    break
elif [ $rc -eq 1 ]; then
    echo "[zirc] Hangup detected, stopping restart loop."
    break
else
    echo "[zirc] rlwrap exited with code $rc. Manual restart required."
    read -r -p "[zirc] Press Enter to restart rlwrap or Ctrl-C to exit..." _
fi
done

exit 0
