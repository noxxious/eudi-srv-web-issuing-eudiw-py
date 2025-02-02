from app_config.config_service import ConfService as cfgserv
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO


def add_number_to_image(image_path, number):
    logger = cfgserv.app_logger

    with Image.open(image_path) as img:
        img = img.convert("RGB")  # Ensure RGB mode for saving as JPG
        draw = ImageDraw.Draw(img)

        # Load the Arial font
        font_path = Path(__file__).parent / "static" / "arial.ttf"
        try:
            font = ImageFont.truetype(font_path, size=150)
        except IOError:
            logger.error(
                "No suitable font found. Please ensure a font is bundled with the application."
            )
            raise ValueError(
                "No suitable font found. Please ensure a font is bundled with the application."
            )

        # Prepare text and calculate its position
        text = str(number)
        text_width = font.getlength(text)
        font_ascent, font_descent = font.getmetrics()
        text_height = font_ascent + font_descent

        img_width, img_height = img.size
        position = ((img_width - text_width) // 2, (img_height - text_height) // 2)

        draw.text(position, text, font=font, fill=(200, 0, 0))  # Red text

        # Save the modified image to a BytesIO object
        img_byte_array = BytesIO()
        img.save(img_byte_array, format="JPEG")
        img_byte_array.seek(0)

        # Encode the image to base64
        base64_encoded_image = base64.b64encode(img_byte_array.read()).decode("utf-8")

        return base64_encoded_image


def convert_image_to_base64(image_path):
    with open(image_path, "rb") as imagefile:
        return base64.b64encode(imagefile.read()).decode("utf-8")
