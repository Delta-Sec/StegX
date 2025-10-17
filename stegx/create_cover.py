from PIL import Image

img = Image.new("RGB", (100, 100), color="blue")
img.save("cover_image.png")

print("Created cover_image.png")
