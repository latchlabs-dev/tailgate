"""Original Tailgate mark: an open gate connecting three network endpoints.

Generate the vector and a deterministic 120 x 120 RGBA PNG using only stdlib.
This is new geometric artwork, not a Tailscale/Google logo or a raster edit.
"""
import math
from pathlib import Path
import struct
import zlib

SVG = '''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 120 120" role="img" aria-labelledby="title">
<title id="title">Tailgate</title>
<rect x="4" y="4" width="112" height="112" rx="25" fill="#23432f"/>
<path d="M34 88V42H62V76H88V32" fill="none" stroke="#f5faf3" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="34" cy="88" r="9" fill="#c9e891"/>
<circle cx="62" cy="42" r="9" fill="#c9e891"/>
<circle cx="88" cy="32" r="9" fill="#c9e891"/>
</svg>\n'''
SEGMENTS = [(34, 88, 34, 42), (34, 42, 62, 42), (62, 42, 62, 76),
            (62, 76, 88, 76), (88, 76, 88, 32)]


def segment_distance(x, y, a, b, c, d):
    t = max(0.0, min(1.0, ((x-a)*(c-a)+(y-b)*(d-b))/((c-a)**2+(d-b)**2)))
    return math.hypot(x-a-t*(c-a), y-b-t*(d-b))


def pixel(x, y):
    # Rounded square signed-distance check, radius 25.
    qx, qy = abs(x-60)-31, abs(y-60)-31
    distance = math.hypot(max(qx, 0), max(qy, 0))+min(max(qx, qy), 0)-25
    if distance > 0:
        return (0, 0, 0, 0)
    color = (35, 67, 47, 255)
    if any(segment_distance(x, y, *s) <= 5 for s in SEGMENTS):
        color = (245, 250, 243, 255)
    if any(math.hypot(x-a, y-b) <= 9 for a, b in [(34, 88), (62, 42), (88, 32)]):
        color = (201, 232, 145, 255)
    return color


def png():
    rows = bytearray()
    for y in range(120):
        rows.append(0)
        for x in range(120):
            samples = [pixel(x+(a+.5)/4, y+(b+.5)/4) for a in range(4) for b in range(4)]
            alpha = sum(p[3] for p in samples)
            # Premultiplied sampling avoids a dark fringe around transparency.
            rgba = [round(sum(p[c]*p[3] for p in samples)/alpha) if alpha else 0 for c in range(3)]
            rgba.append(round(alpha/16))
            rows.extend(rgba)
    def chunk(kind, data):
        return struct.pack('>I', len(data))+kind+data+struct.pack('>I', zlib.crc32(kind+data)&0xffffffff)
    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR', struct.pack('>IIBBBBB', 120, 120, 8, 6, 0, 0, 0))+
            chunk(b'IDAT', zlib.compress(bytes(rows), 9))+chunk(b'IEND', b''))


def write_assets(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'tailgate-logo.svg').write_text(SVG, encoding='utf-8')
    (directory/'tailgate-logo.png').write_bytes(png())


if __name__ == '__main__':
    write_assets(Path(__file__).parent/'assets')
