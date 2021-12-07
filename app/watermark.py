import random
from wsgiref.util import FileWrapper

from PIL import Image
import tempfile

from django.conf import settings
from django.http import StreamingHttpResponse
from PIL import Image, ImageDraw, ImageFont
import skimage
import skimage.transform
# from .models import Article

def image_watermark(image,url):
    im = Image.open(f'media/image/{image}')
    watermark = Image.open('media/watermark.jpg')
    x, y = im.size
    print(x,y)
    im.paste(watermark, (100,100))
    im.show()
    # model = Article.objects.filter(url = url).update(image = im.file)
    # print(model)
    # return im.save("media/redactd/")

def text_watermark(image):
    name = 'Ti pidor'
    print(image)
    original_image = Image.open(f"media/image/{image}")
    print(original_image)
    original_image_size = original_image.size
    font = ImageFont.truetype('arial.ttf', 55)
    # font = ImageFont.load_default()

    text_size = font.getsize(name)
    text_image = Image.new('RGBA', text_size, (255, 255, 255, 0))
    text_draw = ImageDraw.Draw(text_image)
    text_draw.text((0, 0), name, (255, 255, 255, 129), font=font)
    rotated_text_image = text_image.rotate(45, expand=True, fillcolor=(0, 0, 0, 0))
    rotated_text_image_size = rotated_text_image.size
    combined_image = original_image
    parts = 8
    offset_x = original_image_size[0] // parts
    offset_y = original_image_size[1] // parts
    start_x = original_image_size[0] // parts - rotated_text_image_size[0] // 2
    start_y = original_image_size[1] // parts - rotated_text_image_size[1] // 2
    for a in range(0, parts, 2):
        for b in range(0, parts, 2):
            x = start_x + a * offset_x
            y = start_y + b * offset_y
            # image with the same size and transparent color (..., ..., ..., 0)
            watermarks_image = Image.new('RGBA', original_image_size, (255, 255, 255, 0))
            # put text in expected place on watermarks image
            watermarks_image.paste(rotated_text_image, (x, y))
            # put watermarks image on original image
            combined_image = Image.alpha_composite(combined_image, watermarks_image)
    combined_image.show()
    combined_image.save(f'watermark_{name}.png')