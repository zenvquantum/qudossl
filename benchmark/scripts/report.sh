#!/usr/bin/env bash
# Generates REPORT.md (and REPORT.pdf when pandoc is available) from data/.
#
# Usage: ./scripts/report.sh [data-dir]
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
set -e
DS=${1:-$DATA}
[ -d "$DS" ] || { echo "FATAL: $DS not found" >&2; exit 1; }
MD=$BENCH/REPORT.md
python3 "$_lib/analyze.py" "$DS" > "$MD.tmp" && mv "$MD.tmp" "$MD"
{
  echo; echo "## Provenance"; echo
  echo "| file | rows | sha256 |"; echo "|---|---|---|"
  for f in "$DS"/*.csv; do
    [ -f "$f" ] || continue
    printf '| `%s` | %s | `%s` |\n' "$(basename "$f")" "$(( $(wc -l < "$f") - 1 ))" \
      "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$f" | cut -d' ' -f1)"
  done
  echo
  echo "Tools: OpenSSL perftools and ctz/openssl-bench, both vendored under"
  echo "\`benchmark/\`, each built once against each OpenSSL tree."
  echo
  echo "Generated $(date -u '+%Y-%m-%dT%H:%M:%SZ') on $(uname -srm)."
} >> "$MD"
echo "wrote $MD" >&2
if command -v pandoc >/dev/null 2>&1 && [ -f "$_lib/report.css" ]; then
  H=$BENCH/.report.html
  # The table of contents is only requested for weasyprint, which supports
  # internal links in the PDF.
  TOC=""
  command -v weasyprint >/dev/null 2>&1 && TOC="--toc --toc-depth=2"
  pandoc "$MD" -o "$H" --standalone $TOC \
    --metadata title="qudossl crypto benchmark" --css "$_lib/report.css" --embed-resources 2>/dev/null \
    || pandoc "$MD" -o "$H" --standalone --css "$_lib/report.css" 2>/dev/null

  if command -v weasyprint >/dev/null 2>&1; then
    weasyprint "$H" "$BENCH/REPORT.pdf" 2>/dev/null \
      && echo "wrote $BENCH/REPORT.pdf" >&2 \
      || echo "WARNING: weasyprint failed; $MD is still valid" >&2
  elif command -v wkhtmltopdf >/dev/null 2>&1; then
    wkhtmltopdf --quiet --enable-local-file-access --page-size A4 \
      --margin-top 15mm --margin-bottom 15mm --margin-left 15mm --margin-right 15mm \
      "$H" "$BENCH/REPORT.pdf" 2>/dev/null && echo "wrote $BENCH/REPORT.pdf" >&2
  else
    cp "$H" "$BENCH/REPORT.html"
    echo "WARNING: no HTML-to-PDF converter; wrote $BENCH/REPORT.html instead" >&2
  fi
else
  echo "WARNING: pandoc absent; $MD is still valid" >&2
fi
