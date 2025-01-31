from PIL import Image, ImageDraw, ImageFont
import base64
from io import BytesIO

def add_number_to_image(image_path, number):
    # Open the image file
    with Image.open(image_path) as img:
        # Prepare to draw on the image
        draw = ImageDraw.Draw(img)

        # Load default font (without needing a specific .ttf file)
        font = ImageFont.load_default()

        # Text to be written on the image
        text = str(number)

        # Get size of the image and text to center the text
        img_width, img_height = img.size

        # Use textbbox to get the bounding box of the text
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]  # Width of the bounding box
        text_height = bbox[3] - bbox[1]  # Height of the bounding box

        position = ((img_width - text_width) // 2, (img_height - text_height) // 2)

        temp_img = Image.new('RGBA', img.size, (0, 0, 0, 0))  # RGBA with full transparency
        temp_draw = ImageDraw.Draw(temp_img)

        temp_draw.text(position, text, font=font)  # No 'fill' argument here

        for y in range(bbox[1], bbox[3]):
            for x in range(bbox[0], bbox[2]):
                current_color = temp_img.getpixel((x, y))
                # If the pixel is not transparent, set it to red
                if current_color != (0, 0, 0, 0):  # Check if it's not transparent
                    temp_img.putpixel((x, y), (255, 0, 0, 255))  # Set pixel to red (with full opacity)

        # Paste the text image onto the original image
        img.paste(temp_img, (0, 0), temp_img)  # The third argument is the alpha mask

        # Save the modified image to a BytesIO object
        img_byte_array = BytesIO()
        img.save(img_byte_array, format='JPEG')  # Save as PNG to retain transparency if needed
        img_byte_array.seek(0)

        # Encode the image to base64
        base64_encoded_image = base64.b64encode(img_byte_array.read()).decode('utf-8')

        return base64_encoded_image

def convert_image_to_base64(image_path):
    with open(image_path, "rb") as imagefile:
        return base64.b64encode(imagefile.read()).decode('utf-8')