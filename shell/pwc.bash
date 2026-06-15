# pwc bash integration - records minimal terminal metadata each prompt.
# Source from ~/.bashrc:   source /path/to/shell/pwc.bash
# Captures: cwd, shell, user, host, last command, exit code, recent history.
# Does NOT capture live stdout/stderr (use `pwc run` for captured execution).

PWC_CONTEXT_FILE="${PWC_CONTEXT_FILE:-$HOME/.cache/pwc/context.json}"
mkdir -p "$(dirname "$PWC_CONTEXT_FILE")" 2>/dev/null

__pwc_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

__pwc_record() {
  local ec="$?"
  local last_cmd hist
  last_cmd="$(HISTTIMEFORMAT= history 1 2>/dev/null | sed 's/^ *[0-9]\+ *//')"
  hist="$(HISTTIMEFORMAT= history 15 2>/dev/null | sed 's/^ *[0-9]\+ *//' \
          | sed ':a;N;$!ba;s/\n/","/g')"
  {
    printf '{'
    printf '"cwd":"%s",' "$(__pwc_json_escape "$PWD")"
    printf '"shell":"bash",'
    printf '"user":"%s",' "$(__pwc_json_escape "${USER:-$(id -un)}")"
    printf '"hostname":"%s",' "$(__pwc_json_escape "$(hostname)")"
    printf '"exit_code":%s,' "${ec:-0}"
    printf '"last_command":"%s",' "$(__pwc_json_escape "$last_cmd")"
    printf '"recent_history":["%s"]' "$(__pwc_json_escape "$hist")"
    printf '}'
  } > "$PWC_CONTEXT_FILE" 2>/dev/null
  return $ec
}

case "$PROMPT_COMMAND" in
  *__pwc_record*) : ;;
  *) PROMPT_COMMAND="__pwc_record${PROMPT_COMMAND:+; $PROMPT_COMMAND}" ;;
esac

# Convenience: `ai` alias mapping to pwc (optional).
alias ai='pwc'
