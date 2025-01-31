import logging
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_number_to_image(image_path, number):
    # Open the image file
    with Image.open(image_path) as img:
        img = img.convert('RGB')

        # Prepare to draw on the image
        draw = ImageDraw.Draw(img)

        font_path = Path(__file__).parent / 'static' / 'fontawesome-free-5.15.4-web' / 'webfonts' / 'fa-solid-900.ttf'
        try:
            font = ImageFont.truetype(font_path, size=100)  # Adjust the size as needed
        except IOError as e:
            logger.error(f"Failed to load Font Awesome font from {font_path}: {e}")
            font = ImageFont.load_default()  # Fallback to the default font if Font Awesome fails

        text = str(number)

        bbox = draw.textbbox((0, 0), text, font=font)

        # Calculate text width and height from the bounding box
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        # Get the size of the image
        img_width, img_height = img.size

        # Calculate position to center the text
        position = ((img_width - text_width) // 2, (img_height - text_height) // 2)

        # Draw the text directly on the image (using red color)
        draw.text(position, text, font=font, fill=(255, 0, 0))

        # Save the modified image to a BytesIO object (JPG format)
        img_byte_array = BytesIO()
        img.save(img_byte_array, format='JPEG')  # Save as JPG (JPEG format)
        img_byte_array.seek(0)

        # Encode the image to base64
        base64_encoded_image = base64.b64encode(img_byte_array.read()).decode('utf-8')

        return base64_encoded_image

def convert_image_to_base64(image_path):
    with open(image_path, "rb") as imagefile:
        return base64.b64encode(imagefile.read()).decode('utf-8')