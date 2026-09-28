"""Draw the 1280x640 social-preview / Open Graph image (docs/assets/social-preview.png) and the PNG favicons.

The image is the GitHub social preview and the og:image of the project website; favicon-48.png and
apple-touch-icon.png (180x180) are fallbacks for browsers and devices that do not use favicon.svg. Needs Pillow; uses Segoe UI when
present (Windows), else DejaVu Sans, else Pillow's default font.

    python experiments/make_social_image.py
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "assets", "social-preview.png")
W, H = 1280, 640
S = 2  # supersampling for smooth edges


def font(bold, size):
    for name in (("segoeuib.ttf" if bold else "segoeui.ttf"), ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")):
        for d in (r"C:\Windows\Fonts", "/usr/share/fonts/truetype/dejavu", "/Library/Fonts"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                return ImageFont.truetype(p, size * S)
    return ImageFont.load_default()


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def hexc(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def logo(size):
    """Gradient tile with a white chain-link and a magnifier."""
    n = size * S
    tile = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    grad = Image.new("RGBA", (n, n))
    gd = ImageDraw.Draw(grad)
    a, b = hexc("#3987e5"), hexc("#9d7ce8")
    for i in range(2 * n):
        gd.line([(i, 0), (0, i)], fill=lerp(a, b, i / (2 * n)) + (255,), width=2)
    mask = Image.new("L", (n, n), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, n - 1, n - 1], radius=int(n * 0.25), fill=255)
    tile.paste(grad, (0, 0), mask)
    # chain link: two rounded rectangles drawn upright, then rotated 45 degrees
    m = n * 2
    link = Image.new("RGBA", (m, m), (0, 0, 0, 0))
    ld = ImageDraw.Draw(link)
    w, h, sw = int(n * 0.30), int(n * 0.46), int(n * 0.075)
    cx = m // 2
    ld.rounded_rectangle([cx - w // 2, m // 2 - h + int(h * 0.18), cx + w // 2, m // 2 + int(h * 0.18)],
                         radius=w // 2, outline=(255, 255, 255, 255), width=sw)
    ld.rounded_rectangle([cx - w // 2, m // 2 - int(h * 0.18), cx + w // 2, m // 2 + h - int(h * 0.18)],
                         radius=w // 2, outline=(255, 255, 255, 255), width=sw)
    link = link.rotate(45, resample=Image.BICUBIC).crop((m // 4, m // 4, m * 3 // 4, m * 3 // 4))
    link = link.resize((int(n * 0.78), int(n * 0.78)), Image.LANCZOS)
    tile.alpha_composite(link, (int(n * 0.08), int(n * 0.06)))
    # magnifier badge
    td = ImageDraw.Draw(tile)
    r, c = int(n * 0.16), (int(n * 0.71), int(n * 0.71))
    td.ellipse([c[0] - r, c[1] - r, c[0] + r, c[1] + r], fill=(255, 255, 255, 255))
    r2 = int(n * 0.085)
    td.ellipse([c[0] - r2, c[1] - r2, c[0] + r2, c[1] + r2], outline=hexc("#6d5fe0") + (255,), width=int(n * 0.04))
    td.line([(c[0] + int(r2 * 0.75), c[1] + int(r2 * 0.75)), (c[0] + int(r * 0.85), c[1] + int(r * 0.85))],
            fill=hexc("#6d5fe0") + (255,), width=int(n * 0.04))
    return tile


def pill(d, x, y, label, bg, fg, size=26):
    f = font(True, size)
    tw = d.textlength(label, font=f)
    ph, pw = int(size * 1.9) * S, tw + 2 * 26 * S
    d.rounded_rectangle([x, y, x + pw, y + ph], radius=ph // 2, fill=hexc(bg))
    d.text((x + pw / 2, y + ph / 2), label, font=f, fill=hexc(fg), anchor="mm")
    return pw


def main():
    img = Image.new("RGBA", (W * S, H * S))
    d = ImageDraw.Draw(img)
    top, bot = hexc("#0d1117"), hexc("#16213a")
    for yy in range(H * S):
        d.line([(0, yy), (W * S, yy)], fill=lerp(top, bot, yy / (H * S)) + (255,))
    for gx in range(0, W * S, 44 * S):  # faint dot grid
        for gy in range(0, H * S, 44 * S):
            d.ellipse([gx, gy, gx + 3 * S, gy + 3 * S], fill=(35, 43, 54, 255))
    img.alpha_composite(logo(132), (96 * S, 118 * S))
    d.text((260 * S, 124 * S), "fraudurl", font=font(True, 118), fill=(240, 246, 252))
    d.text((98 * S, 300 * S), "Fast, offline phishing URL detector", font=font(True, 50), fill=(240, 246, 252))
    d.text((98 * S, 378 * S), "Check one URL or a whole CSV list for phishing links, offline.", font=font(False, 30),
           fill=(145, 152, 161))
    d.text((98 * S, 420 * S), "One Python file  ·  zero dependencies  ·  plain-English reasons", font=font(False, 30),
           fill=(145, 152, 161))
    x = 98 * S
    for label, bg, fg in (("FRAUD", "#d03b3b", "#ffffff"), ("REVIEW", "#c98500", "#0d1117"),
                          ("LEGITIMATE", "#3987e5", "#ffffff")):
        x += pill(d, x, 490 * S, label, bg, fg) + 16 * S
    d.text((W * S - 96 * S, 570 * S), "github.com/amruth112/fraudurl-detector", font=font(False, 24),
           fill=(118, 131, 144), anchor="ra")
    img = img.resize((W, H), Image.LANCZOS).convert("RGB")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.save(OUT, optimize=True)
    print("wrote", OUT, os.path.getsize(OUT), "bytes")
    for name, px in (("favicon-48.png", 48), ("apple-touch-icon.png", 180)):
        path = os.path.join(os.path.dirname(OUT), name)
        icon = logo(px).resize((px, px), Image.LANCZOS)
        if name.startswith("apple"):  # iOS rounds the corners itself: fill the square edge to edge
            big = logo(px * 9 // 8)
            k = (big.width - px * S) // 2
            icon = big.crop((k, k, k + px * S, k + px * S)).resize((px, px), Image.LANCZOS)
            icon = Image.alpha_composite(Image.new("RGBA", (px, px), (57, 135, 229, 255)), icon).convert("RGB")
        icon.save(path, optimize=True)
        print("wrote", path, os.path.getsize(path), "bytes")


if __name__ == "__main__":
    main()
