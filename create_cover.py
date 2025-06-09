from PIL import Image

# Create a simple 100x100 RGB image
img = Image.new("RGB", (100, 100), color = "blue")
img.save("/home/ubuntu/stegx_project/cover_image.png")

print("Created cover_image.png")
