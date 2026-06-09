#!/usr/bin/env python3
"""Generate an animated terminal demo SVG for the README (pure SMIL, loops on GitHub)."""

W, H = 920, 520
LOOP = 13.0            # seconds per loop
BG, BAR = "#0d1117", "#161b22"
FG, DIM = "#c9d1d9", "#8b949e"
GREEN, CYAN, YEL = "#3fb950", "#39c5cf", "#d29922"
RED, ORANGE, GREY = "#f85149", "#db8e1c", "#6e7681"
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"

# (text, x, color, size, weight, appear_time)
prompt_t = 0.4
lines = [
    ('<tspan fill="%s">$</tspan> <tspan fill="%s">chainedr scan ./contracts --no-external</tspan>' % (GREEN, FG), 28, FG, 17, "bold", prompt_t),
    ('ChainEDR v3.0.0 — EIP-7702 / account-abstraction analyzer', 28, DIM, 14, "normal", 1.6),
    ('[*] scanning ./contracts …', 28, CYAN, 14, "normal", 2.3),
    ('', 0, FG, 14, "normal", 0),  # spacer
]

# findings: (id, title, sev, sevcolor, verdict, vcolor, t)
findings = [
    ("AA7702-009", "ERC-1967 proxy as delegation target", "CRIT", RED,   "UNCERTAIN", YEL,   3.2),
    ("AA7702-002", "code.length EOA check broken by 7702", "HIGH", ORANGE,"CONFIRM",   GREEN, 4.0),
    ("AA7702-004", "signed action missing chain_id",       "MED",  YEL,   "UNCERTAIN", YEL,   4.8),
    ("AA7702-016", "ecrecover without EIP-1271 fallback",  "MED",  YEL,   "UNCERTAIN", YEL,   5.6),
]
summary_t = 6.6
clear_t = LOOP - 0.8

def appear(t):
    """SMIL: opacity 0 -> 1 at t, then clear near loop end, repeating each loop."""
    return (
        '<animate attributeName="opacity" from="0" to="1" begin="loop.begin+%ss" dur="0.28s" fill="freeze"/>'
        '<animate attributeName="opacity" to="0" begin="loop.begin+%ss" dur="0.25s" fill="freeze"/>'
        % (t, clear_t)
    )

out = []
out.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{MONO}">')
out.append(f'<rect width="{W}" height="{H}" rx="12" fill="{BG}"/>')
out.append(f'<rect width="{W}" height="40" rx="12" fill="{BAR}"/>')
out.append(f'<rect y="20" width="{W}" height="20" fill="{BAR}"/>')
for i, c in enumerate(["#ff5f56", "#ffbd2e", "#27c93f"]):
    out.append(f'<circle cx="{26+i*22}" cy="20" r="6" fill="{c}"/>')
out.append(f'<text x="{W/2}" y="25" fill="{DIM}" font-size="13" text-anchor="middle">chainedr — terminal</text>')

# invisible master loop clock
out.append(f'<rect x="-10" y="-10" width="1" height="1" fill="none">'
           f'<animate id="loop" attributeName="x" begin="0s;loop.end" dur="{LOOP}s" from="-10" to="-10"/></rect>')

y = 78
# command + status lines
for txt, x, color, size, weight, t in lines:
    if not txt:
        y += 14
        continue
    out.append(f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" font-weight="{weight}" opacity="0">{txt}{appear(t)}</text>')
    y += 30

# blinking cursor at end of typed command (after it appears)
out.append(f'<rect x="500" y="64" width="9" height="18" fill="{GREEN}" opacity="0">'
           f'<animate attributeName="opacity" values="0;1;1;0;0" dur="1s" begin="loop.begin+{prompt_t}s" repeatCount="6"/></rect>')

y += 6
# findings rows
for fid, title, sev, sc, verdict, vc, t in findings:
    out.append(f'<g opacity="0">{appear(t)}')
    out.append(f'<rect x="28" y="{y-15}" width="{W-56}" height="26" rx="6" fill="#1b2330"/>')
    # severity pill
    out.append(f'<rect x="40" y="{y-12}" width="52" height="20" rx="10" fill="{sc}" opacity="0.18"/>')
    out.append(f'<text x="66" y="{y+2}" fill="{sc}" font-size="12" font-weight="bold" text-anchor="middle">{sev}</text>')
    out.append(f'<text x="108" y="{y+2}" fill="{CYAN}" font-size="13" font-weight="bold">{fid}</text>')
    out.append(f'<text x="210" y="{y+2}" fill="{FG}" font-size="13">{title}</text>')
    # verdict dot + label (right aligned)
    out.append(f'<circle cx="{W-150}" cy="{y-3}" r="5" fill="{vc}"/>')
    out.append(f'<text x="{W-138}" y="{y+2}" fill="{vc}" font-size="12" font-weight="bold">{verdict}</text>')
    out.append('</g>')
    y += 34

# summary line
y += 14
out.append(f'<text x="28" y="{y}" fill="{GREEN}" font-size="14" font-weight="bold" opacity="0">'
           f'✔ 30 dedicated checks · 8 sandbox boundaries · verdict-labelled{appear(summary_t)}</text>')
y += 26
out.append(f'<text x="28" y="{y}" fill="{DIM}" font-size="13" opacity="0">'
           f'benchmark F1 = 1.00, corpus-scoped  ·  fair competitor run pending{appear(summary_t+0.5)}</text>')

out.append('</svg>')
open("docs/assets/demo.svg", "w", encoding="utf-8").write("\n".join(out))
print("wrote docs/assets/demo.svg")
