from pathlib import Path
import cairosvg

svg = Path('static/logo.svg')
png = Path('static/logo.png')
# Render at 256x256 to ensure consistent box size and padding from SVG
cairosvg.svg2png(url=str(svg), write_to=str(png), output_width=256, output_height=256)
print('Rendered', png)
