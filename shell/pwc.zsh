# pwc zsh integration - records minimal terminal metadata each prompt.
# Source from ~/.zshrc:   source /path/to/shell/pwc.zsh

PWC_CONTEXT_FILE="${PWC_CONTEXT_FILE:-$HOME/.cache/pwc/context.json}"
mkdir -p "$(dirname "$PWC_CONTEXT_FILE")" 2>/dev/null

__pwc_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

__pwc_record() {
  local ec=$?
  local last_cmd hist
  last_cmd="$(fc -ln -1 2>/dev/null | sed 's/^ *//')"
  hist="$(fc -ln -15 2>/dev/null | sed 's/^ *//' | paste -sd '\n' - \
          | sed ':a;N;$!ba;s/\n/","/g')"
  {
    printf '{'
    printf '"cwd":"%s",' "$(__pwc_json_escape "$PWD")"
    printf '"shell":"zsh",'
    printf '"user":"%s",' "$(__pwc_json_escape "${USER:-$(id -un)}")"
    printf '"hostname":"%s",' "$(__pwc_json_escape "$(hostname)")"
    printf '"exit_code":%s,' "${ec:-0}"
    printf '"last_command":"%s",' "$(__pwc_json_escape "$last_cmd")"
    printf '"recent_history":["%s"]' "$(__pwc_json_escape "$hist")"
    printf '}'
  } > "$PWC_CONTEXT_FILE" 2>/dev/null
  return $ec
}

autoload -Uz add-zsh-hook 2>/dev/null
add-zsh-hook precmd __pwc_record 2>/dev/null

alias ai='pwc'
