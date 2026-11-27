# Sourced by the hook wrappers. Git for Windows runs hooks with its own sh, where `python3`
# can be the Microsoft Store stub, so each candidate is probed by running it.
for py in python3 python "py -3"; do
  if $py -c "import sys; sys.exit(sys.version_info < (3, 9))" >/dev/null 2>&1; then
    exec $py "$(dirname "$0")/hooks.py" "$(basename "$0")" "$@"
  fi
done
echo "$(basename "$0"): no working Python 3 found (tried python3, python, py -3)" >&2
exit 1
