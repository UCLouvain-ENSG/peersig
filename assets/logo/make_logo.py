#!/usr/bin/env python3
"""PeerSig's logo: a fingerprint drawn with dots. Each anonymous ballot is a
dot; together they make the signature database.

Writes the SVG sources next to this script. `render.sh` turns them into the
app and menu-bar icons.
"""
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CX, CY, ROT = 512, 500, -14  # print centre and tilt (degrees)

# Ridges: x radius, and the arcs drawn (degrees; 270 is the top, the bottom is open).
FULL = [
    (40, [(200, 470)]),
    (100, [(150, 330), (350, 410)]),
    (160, [(128, 250), (268, 420)]),
    (220, [(120, 300), (320, 414)]),
    (280, [(114, 214), (232, 418)]),
]
# Menu-bar glyph: fewer ridges, wide gaps, solid strokes (dots vanish at 18 pt).
MARK = [
    (70, [(190, 470)]),
    (175, [(140, 300), (328, 412)]),
    (280, [(120, 236), (262, 416)]),
]


def point(rx, ry, deg):
    t, f = math.radians(deg), math.radians(ROT)
    x, y = rx * math.cos(t), ry * math.sin(t)
    return CX + x * math.cos(f) - y * math.sin(f), CY + x * math.sin(f) + y * math.cos(f)


def arc(rx, ry, a0, a1):
    (x0, y0), (x1, y1) = point(rx, ry, a0), point(rx, ry, a1)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    return f"M {x0:.1f} {y0:.1f} A {rx:.1f} {ry:.1f} {ROT} {large} 1 {x1:.1f} {y1:.1f}"


def ridges(spec, color, width, dots=False):
    paths = "".join(f'<path d="{arc(rx, rx * 1.3, a0, a1)}"/>' for rx, segs in spec for a0, a1 in segs)
    dash = ' stroke-dasharray="0 64"' if dots else ""
    return f'<g fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round"{dash}>{paths}</g>'


def place(g, scale, cy):
    return f'<g transform="translate(512 520) scale({scale}) translate(-512 -{cy})">{g}</g>'


def svg(body, view="0 0 1024 1024"):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}">{body}</svg>\n'


def icon():
    return svg(
        '<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">'
        '<stop offset="0" stop-color="#4338ca"/><stop offset="1" stop-color="#0d9488"/></linearGradient></defs>'
        '<rect x="100" y="100" width="824" height="824" rx="185" fill="url(#bg)"/>'
        + place(ridges(FULL, "#ffffff", 50, dots=True), 0.72, 450)
    )


MARK_VIEW = "112 112 800 800"


def mark(opacity=1.0):
    return svg(f'<g opacity="{opacity}">{place(ridges(MARK, "#000000", 64), 1.0, 440)}</g>', MARK_VIEW)


def mark_sending():
    # The print, cut around an upload arrow in the lower right.
    cut = ('<defs><mask id="cut"><rect x="0" y="0" width="1024" height="1024" fill="#fff"/>'
           '<circle cx="770" cy="740" r="190" fill="#000"/></mask></defs>')
    arrow = ('<g fill="none" stroke="#000000" stroke-width="72" stroke-linecap="round" stroke-linejoin="round">'
             '<path d="M 770 860 L 770 620"/><path d="M 680 710 L 770 620 L 860 710"/></g>')
    return svg(cut + f'<g mask="url(#cut)">{place(ridges(MARK, "#000000", 64), 1.0, 440)}</g>' + arrow, MARK_VIEW)


if __name__ == "__main__":
    out = {
        "peersig.svg": icon(),
        "peersig-mark.svg": mark(),
        "peersig-mark-paused.svg": mark(0.4),
        "peersig-mark-sending.svg": mark_sending(),
    }
    for name, text in out.items():
        with open(os.path.join(HERE, name), "w") as f:
            f.write(text)
        print(name)
