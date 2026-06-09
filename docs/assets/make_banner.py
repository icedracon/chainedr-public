#!/usr/bin/env python3
"""Generate the GitHub social-preview banner (1280x640 PNG) with Pillow."""
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
F = "C:/Windows/Fonts/"
def font(name, size): return ImageFont.truetype(F + name, size)

seg_bold = lambda s: font("segoeuib.ttf", s)
seg = lambda s: font("segoeui.ttf", s)
seg_light = lambda s: font("segoeuil.ttf", s)
mono = lambda s: font("consolab.ttf", s)

BG_TOP, BG_BOT = (13, 17, 23), (22, 16, 38)     # dark -> deep violet
FG, DIM = (230, 237, 243), (139, 148, 158)
ACCENT = (138, 43, 226)                          # blueviolet
CYAN, GREEN, RED, YEL, ORANGE = (57,197,207),(63,185,80),(248,81,73),(210,153,34),(219,142,28)

img = Image.new("RGB", (W, H), BG_TOP)
px = img.load()
# vertical gradient
for y in range(H):
    t = y / H
    px_row = tuple(int(BG_TOP[i] + (BG_BOT[i]-BG_TOP[i])*t) for i in range(3))
    for x in range(W):
        px[x, y] = px_row
d = ImageDraw.Draw(img, "RGBA")

# subtle dot grid
for gy in range(40, H, 40):
    for gx in range(40, W, 40):
        d.ellipse([gx-1, gy-1, gx+1, gy+1], fill=(255, 255, 255, 12))

# accent corner glow
for r in range(420, 0, -6):
    a = int(22 * (r/420))
    d.ellipse([W-260-r//2, -120-r//2, W-260+r//2, -120+r//2], fill=(138, 43, 226, max(0, 18-a//3)))

# left accent bar
d.rounded_rectangle([72, 150, 84, 360], radius=6, fill=ACCENT)

# chain-link glyph (two interlocked rounded rects) near title
lx, ly = 110, 150
d.rounded_rectangle([lx, ly+6, lx+46, ly+34], radius=14, outline=ACCENT, width=7)
d.rounded_rectangle([lx+30, ly+22, lx+76, ly+50], radius=14, outline=CYAN, width=7)

# title
d.text((110, 196), "ChainEDR", font=seg_bold(116), fill=FG)
# tagline
d.text((114, 330), "Security analysis for the EVM's newest attack surface", font=seg(34), fill=DIM)
d.text((114, 376), "EIP-7702 delegated accounts  ·  ERC-4337 account abstraction",
       font=seg_bold(34), fill=CYAN)

# stat chips
def chip(x, y, big, small, color):
    w = 250
    d.rounded_rectangle([x, y, x+w, y+96], radius=16, fill=(255,255,255,10), outline=(color[0],color[1],color[2],120), width=2)
    d.text((x+22, y+16), big, font=seg_bold(40), fill=color)
    d.text((x+22, y+62), small, font=seg(20), fill=DIM)

cy = 470
chip(114, cy, "30", "dedicated checks", ACCENT)
chip(394, cy, "F1 1.00", "on benchmark", GREEN)
chip(674, cy, "8", "sandbox boundaries", CYAN)
chip(954, cy, "0", "rivals cover 7702", RED)

# boundary mini-legend (top right)
bx, by = 905, 150
d.text((bx, by), "SANDBOX BOUNDARIES", font=seg_bold(18), fill=DIM)
names = ["identity","code","storage","call","validation","replay","revocation","gas"]
cols  = [CYAN, GREEN, YEL, ORANGE, ACCENT, RED, (120,160,255), (200,120,90)]
for i,(n,c) in enumerate(zip(names, cols)):
    yy = by + 34 + i*26
    d.ellipse([bx, yy+3, bx+12, yy+15], fill=c)
    d.text((bx+22, yy), n, font=mono(19), fill=FG)

# footer brand line
d.text((114, 600), "static + differential analysis  ·  REAL / UNCERTAIN / FALSE_POSITIVE verdicts",
       font=mono(20), fill=DIM)

img.save("docs/assets/social-banner.png", "PNG")
print("wrote docs/assets/social-banner.png", img.size)
