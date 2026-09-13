from PIL import Image
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
FILES = [
    os.path.join(ROOT, 'static', 'js', 'screen.png'),
    os.path.join(ROOT, 'static', 'img', 'image.png'),
    os.path.join(ROOT, 'static', 'logo.cybergard.png'),
]

MAX_WIDTH = 1200
QUALITY = 80

def convert(path):
    if not os.path.exists(path):
        print('Missing:', path)
        return
    dest = os.path.splitext(path)[0] + '.webp'
    try:
        with Image.open(path) as im:
            im = im.convert('RGBA')
            w, h = im.size
            if w > MAX_WIDTH:
                new_h = int(h * MAX_WIDTH / w)
                im = im.resize((MAX_WIDTH, new_h), Image.LANCZOS)
            im.save(dest, 'webp', quality=QUALITY, method=6)
            print(f'Converted {os.path.relpath(path)} -> {os.path.relpath(dest)}')
    except Exception as e:
        print('Failed converting', path, e)

if __name__ == '__main__':
    for p in FILES:
        convert(p)
