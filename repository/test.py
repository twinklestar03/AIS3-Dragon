from twisted import internet
import PIL  
from PIL import Image as img, ImageDraw
from PIL import ImageFont
import numpy as np

a = np.array([[1,2,3,4], [5,6,7,8], [9,10,11,12]]) 

row_r1 = a[1, :]    # Rank 1 view of the second row of a
row_r2 = a[1:2, :]  # Rank 2 view of the second row of a
print(row_r1, row_r1.shape)  # Prints "[5 6 7 8] (4,)"
print(row_r2, row_r2.shape)

im = img.new("RGB", (512, 512), (128, 128, 128))
draw = PIL.ImageDraw.Draw(im)
draw.line((0, im.height, im.width, 0), fill=(255, 0, 0), width=8)
draw.rectangle((100, 100, 200, 200), fill=(0, 255, 0))
draw.ellipse((250, 300, 450, 400), fill=(0, 0, 255))
print("finish")
# im.show()
