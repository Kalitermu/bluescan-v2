cd ~/bluescan-v2

cp app.py app.backup_debug.py

python3 - <<'PY'
from pathlib import Path

p = Path("app.py")
s = p.read_text()

s = s.replace(
    'from target_policy import validate_target',
    'import target_policy\nfrom target_policy import validate_target'
)

s = s.replace(
    'if scan_button:',
    '''if scan_button:

    st.write("DEBUG — target_policy:", target_policy.__file__)
    st.write("DEBUG — validação:", validate_target(target))'''
)

p.write_text(s)
PY