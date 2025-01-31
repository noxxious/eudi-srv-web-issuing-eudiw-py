from app_config.config_service import ConfService as cfgserv
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO

def add_number_to_image(image_path, number):
    # Configure logging
    logger = cfgserv.app_logger
    logger.info("ADD_NUMBER_TO_IMAGE")

    # Open the image file
    with Image.open(image_path) as img:
        # Convert image to RGB mode (required for JPG)
        img = img.convert('RGB')  # Ensure it's in RGB mode for saving as JPG

        # Prepare to draw on the image
        draw = ImageDraw.Draw(img)

        # Path to the Font Awesome font (adjusted for your case)
        font_path = Path(__file__).parent / 'static' / 'fontawesome-free-5.15.4-web' / 'webfonts' / 'fa-solid-900.ttf'

        try:
            # Attempt to load the Font Awesome font with a larger size for visibility
            font = ImageFont.truetype(str(font_path), size=150)  # Convert Path to string
            logger.info(f"Successfully loaded Font Awesome font from {font_path}")
        except IOError:
            logger.error("No suitable font found. Please ensure a font is bundled with the application.")
            raise ValueError("No suitable font found. Please ensure a font is bundled with the application.")

        # Text (can be a number or a Font Awesome icon Unicode)
        text = str(number)  # The number to be added on the image

        # Debug: Draw a simple test text at a fixed position
        debug_position = (10, 10)  # Top-left corner
        draw.text(debug_position, "Test", font=font, fill=(255, 0, 0))  # Red text for better visibility

        # Get the bounding box for the text (to center it)
        bbox = draw.textbbox((0, 0), text, font=font)

        # Calculate text width and height from the bounding box
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        # Get the size of the image
        img_width, img_height = img.size

        # Calculate the position to center the text on the image
        position = ((img_width - text_width) // 2, (img_height - text_height) // 2)

        # Log text position and size for debugging
        logger.info(f"Text position: {position}, Text size: {text_width}x{text_height}")

        # Debug: Draw a rectangle around the text area to visualize the bounding box
        draw.rectangle(bbox, outline="blue")

        # Draw the text directly on the image (using red color for visibility)
        draw.text(position, text, font=font, fill=(255, 0, 0))  # Red text for better visibility

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