"""生成 Claude Guard 应用图标与品牌资源。

几何形状与 web/index.html 中的 #i-guard 盾牌保持一致：
圆角方底 + 渐变盾牌 + 盾内对勾。

运行（仅开发期需要 Pillow）：
    python tools/make_icons.py

输出：
    assets/icon.ico      Windows 窗口与快捷方式图标（多尺寸）
    assets/icon-256.png  高清位图（README / 商店展示）
    assets/logo.svg      矢量 Logo（网页与文档引用）
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
SIZE = 1024
SS = 4  # 超采样倍数，缩小后获得抗锯齿边缘

# 品牌色（与 web/styles.css 的 --accent / --accent-fill 对齐）
TOP = (168, 190, 255)
BOTTOM = (58, 96, 205)
BG_TOP = (44, 47, 58)
BG_BOTTOM = (20, 21, 26)


def _lerp(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))  # type: ignore[return-value]


def _vertical_gradient(size: int, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Image.Image:
    grad = Image.new("RGB", (1, size))
    px = grad.load()
    for y in range(size):
        px[0, y] = _lerp(top, bottom, y / max(1, size - 1))
    return grad.resize((size, size), Image.NEAREST)


def _shield_mask(size: int) -> Image.Image:
    """圆角顶肩 + 抛物线收尖的盾牌遮罩。"""
    s = size * SS
    mask = Image.new("L", (s, s), 0)
    draw = ImageDraw.Draw(mask)

    left, right = 0.262 * s, 0.738 * s
    top, bottom = 0.196 * s, 0.834 * s
    shoulder = top + (bottom - top) * 0.34
    radius = (right - left) * 0.20

    # 上半部分：圆角矩形（顶肩）
    draw.rounded_rectangle([left, top, right, shoulder + radius], radius=radius, fill=255)

    # 下半部分：从两侧收拢到底部尖端
    cx = (left + right) / 2
    half = (right - left) / 2
    pts = []
    steps = 160
    for i in range(steps + 1):
        t = i / steps
        y = shoulder + (bottom - shoulder) * t
        w = half * math.sqrt(max(0.0, 1.0 - t * t))
        pts.append((cx + w, y))
    for i in range(steps, -1, -1):
        t = i / steps
        y = shoulder + (bottom - shoulder) * t
        w = half * math.sqrt(max(0.0, 1.0 - t * t))
        pts.append((cx - w, y))
    draw.polygon(pts, fill=255)

    return mask.resize((size, size), Image.LANCZOS)


def _background(size: int) -> Image.Image:
    s = size * SS
    base = _vertical_gradient(s, BG_TOP, BG_BOTTOM).convert("RGBA")
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.225), fill=255)

    bg = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    bg.paste(base, (0, 0), mask)

    # 顶部柔光，避免纯深色显得死板
    glow = Image.new("L", (s, s), 0)
    ImageDraw.Draw(glow).ellipse(
        [-s * 0.35, -s * 0.62, s * 1.35, s * 0.55], fill=64
    )
    glow = glow.filter(ImageFilterGaussian(s * 0.16))
    shade = Image.new("RGBA", (s, s), (120, 145, 255, 255))
    bg = Image.composite(shade, bg, glow.point(lambda v: v))

    # 极细内描边
    border = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(border).rounded_rectangle(
        [s * 0.012, s * 0.012, s * 0.988, s * 0.988],
        radius=int(s * 0.215),
        outline=(255, 255, 255, 26),
        width=max(1, int(s * 0.006)),
    )
    bg.alpha_composite(border)
    return bg.resize((size, size), Image.LANCZOS)


def ImageFilterGaussian(radius: float):  # noqa: N802 - 读取更直观
    from PIL import ImageFilter

    return ImageFilter.GaussianBlur(radius)


def _shield_layer(size: int) -> Image.Image:
    """带渐变与内高光的盾牌层（透明底）。"""
    s = size * SS
    mask = _shield_mask(size).resize((s, s), Image.LANCZOS)
    fill = _vertical_gradient(s, TOP, BOTTOM).convert("RGBA")

    layer = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    layer.paste(fill, (0, 0), mask)

    # 顶部高光
    highlight = Image.new("RGBA", (s, s), (255, 255, 255, 0))
    hl = Image.new("L", (s, s), 0)
    ImageDraw.Draw(hl).ellipse([s * 0.24, s * 0.16, s * 0.76, s * 0.52], fill=70)
    hl = hl.filter(ImageFilterGaussian(s * 0.05))
    highlight.paste((255, 255, 255, 255), (0, 0), Image.composite(hl, Image.new("L", (s, s), 0), mask))
    layer.alpha_composite(highlight)

    # 对勾（镂空为底色，小尺寸下依然清晰）
    check = Image.new("L", (s, s), 0)
    cd = ImageDraw.Draw(check)
    w = max(2, int(s * 0.078))
    cd.line(
        [(s * 0.372, s * 0.505), (s * 0.462, s * 0.596), (s * 0.648, s * 0.398)],
        fill=255,
        width=w,
        joint="curve",
    )
    for x, y in ((s * 0.372, s * 0.505), (s * 0.648, s * 0.398)):
        cd.ellipse([x - w / 2, y - w / 2, x + w / 2, y + w / 2], fill=255)

    hole = Image.new("RGBA", (s, s), (23, 24, 30, 255))
    layer.paste(hole, (0, 0), Image.composite(check, Image.new("L", (s, s), 0), mask))
    return layer.resize((size, size), Image.LANCZOS)


def render(size: int) -> Image.Image:
    icon = _background(size)
    icon.alpha_composite(_shield_layer(size))
    return icon


def _svg(size: int = 64) -> str:
    """与位图同构的矢量 Logo。"""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="{size}" height="{size}" role="img" aria-label="Claude Guard">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#2c2f3a"/>
      <stop offset="1" stop-color="#14151a"/>
    </linearGradient>
    <linearGradient id="shield" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#a8beff"/>
      <stop offset="1" stop-color="#3a60cd"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="115" fill="url(#bg)"/>
  <rect x="6" y="6" width="500" height="500" rx="110" fill="none" stroke="#ffffff" stroke-opacity=".10" stroke-width="3"/>
  <path d="M126 110h260a56 56 0 0 1 56 56v81c0 92-63 149-186 185-123-36-186-93-186-185v-81a56 56 0 0 1 56-56Z" fill="url(#shield)"/>
  <path d="m190 258 46 46 94-101" fill="none" stroke="#17181e" stroke-width="40" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
"""


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    master = render(SIZE)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    master.save(ASSETS / "icon.ico", sizes=[(s, s) for s in sizes])
    master.resize((256, 256), Image.LANCZOS).save(ASSETS / "icon-256.png")
    (ASSETS / "logo.svg").write_text(_svg(), encoding="utf-8")

    for name in ("icon.ico", "icon-256.png", "logo.svg"):
        path = ASSETS / name
        print(f"{path.relative_to(ROOT)}  {path.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
