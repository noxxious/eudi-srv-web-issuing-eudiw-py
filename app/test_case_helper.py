from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO

def add_number_to_image(image_path, number):
    # Open the image file
    with Image.open(image_path) as img:
        # Prepare to draw on the image
        draw = ImageDraw.Draw(img)

        # Define font (if you don't have a specific font, PIL will use a default one)
        try:
            font = ImageFont.truetype("arial.ttf", size=100)  # Adjust size as necessary
        except IOError:
            font = ImageFont.load_default()

        # Text to be written on the image
        text = str(number)

        # Get size of the image and text to center the text
        img_width, img_height = img.size

        # Use textbbox to get the bounding box of the text
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]  # Width of the bounding box
        text_height = bbox[3] - bbox[1]  # Height of the bounding box

        # Calculate position to center the text
        position = ((img_width - text_width) // 2, (img_height - text_height) // 2)

        # Set the color to red (RGB: 255, 0, 0)
        text_color = (255, 0, 0)

        # Add the text to the image
        draw.text(position, text, font=font, fill=text_color)

        # Save the modified image to a BytesIO object
        img_byte_array = BytesIO()
        img.save(img_byte_array, format='JPG')  # Save image as JPG in memory
        img_byte_array.seek(0)

        # Encode the image to base64
        base64_encoded_image = base64.b64encode(img_byte_array.read()).decode('utf-8')

        return base64_encoded_image

def convert_image_to_base64(image_path):
    with open(image_path, "rb") as imagefile:
        return base64.b64encode(imagefile.read()).decode('utf-8')