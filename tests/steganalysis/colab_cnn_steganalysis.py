# %% [markdown]
# # 🛡️ StegX v2.0 — CNN Steganalysis Resistance Test
# 
# This notebook trains **SRNet** (the gold-standard CNN steganalysis detector) on clean vs StegX stego images,
# then reports detection accuracy. An accuracy near 50% = random guessing = **steganographically invisible**.
#
# **Runtime:** ~2-3 hours on Colab T4 GPU
#
# **Instructions:** Runtime → Change runtime type → GPU (T4) → Run All

# %% Step 0: Install dependencies
import subprocess, sys

subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
    "torch", "torchvision", "pillow", "numpy", "scikit-learn", "matplotlib",
    "stegx-cli[compression]"])

print("All dependencies installed!")

# %% Step 1: Verify StegX is working
result = subprocess.run([sys.executable, "-m", "stegx", "--version"], capture_output=True, text=True)
print(f"StegX version: {result.stdout.strip()}")
if result.returncode != 0:
    print("ERROR: StegX not installed correctly!")
    print(result.stderr)
    raise RuntimeError("StegX installation failed")

# %% [markdown]
# ## 1. Generate Dataset

# %%
import os
import numpy as np
from PIL import Image, ImageDraw, ImageFilter
from pathlib import Path

DATASET_DIR = Path("/content/steganalysis_dataset")
COVER_DIR = DATASET_DIR / "cover"
STEGO_DIR = DATASET_DIR / "stego"
COVER_DIR.mkdir(parents=True, exist_ok=True)
STEGO_DIR.mkdir(parents=True, exist_ok=True)

NUM_IMAGES = 500
IMG_SIZE = (256, 256)

print("Generating cover images...")
for i in range(NUM_IMAGES):
    img_path = COVER_DIR / f"img_{i:04d}.png"
    if img_path.exists():
        if (i+1) % 100 == 0:
            print(f"  {i+1}/{NUM_IMAGES} (cached)")
        continue
    rng = np.random.RandomState(seed=i)
    base = rng.randint(40, 220, size=(*IMG_SIZE, 3), dtype=np.uint8)
    img = Image.fromarray(base, "RGB")
    draw = ImageDraw.Draw(img)
    for _ in range(rng.randint(5, 25)):
        x0, y0 = rng.randint(0, IMG_SIZE[0]-30), rng.randint(0, IMG_SIZE[1]-30)
        x1, y1 = x0 + rng.randint(10, 80), y0 + rng.randint(10, 80)
        draw.rectangle([x0,y0,x1,y1], fill=tuple(rng.randint(0,255,3).tolist()))
    img = img.filter(ImageFilter.GaussianBlur(radius=rng.uniform(0.3, 1.5)))
    noise = rng.randint(-2, 3, size=(*IMG_SIZE, 3), dtype=np.int16)
    arr = np.clip(np.array(img, dtype=np.int16) + noise, 0, 255).astype(np.uint8)
    Image.fromarray(arr, "RGB").save(str(img_path))
    if (i+1) % 100 == 0:
        print(f"  {i+1}/{NUM_IMAGES}")

print(f"Generated {NUM_IMAGES} cover images")

# %%
print("Generating stego images with StegX (adaptive + matrix embedding)...")
secret = DATASET_DIR / "secret.bin"
if not secret.exists():
    with open(secret, "wb") as f:
        f.write(os.urandom(256))

success = 0
errors = []
for i in range(NUM_IMAGES):
    cover = COVER_DIR / f"img_{i:04d}.png"
    stego = STEGO_DIR / f"img_{i:04d}.png"
    if stego.exists():
        success += 1
        if (i+1) % 100 == 0:
            print(f"  {i+1}/{NUM_IMAGES} (success: {success})")
        continue
    try:
        result = subprocess.run(
            [sys.executable, "-m", "stegx", "encode",
             "-i", str(cover), "-f", str(secret), "-o", str(stego),
             "--adaptive", "--matrix-embedding", "--password-stdin"],
            input=b"CnnTestPassword99!",
            capture_output=True, timeout=120
        )
        if result.returncode == 0 and stego.exists():
            success += 1
        else:
            err = result.stderr.decode(errors="replace").strip()
            if len(errors) < 3:
                errors.append(f"Image {i}: {err[:200]}")
    except Exception as e:
        if len(errors) < 3:
            errors.append(f"Image {i}: {str(e)[:200]}")
    if (i+1) % 100 == 0:
        print(f"  {i+1}/{NUM_IMAGES} (success: {success})")

print(f"\nGenerated {success}/{NUM_IMAGES} stego images")
if errors:
    print("Sample errors:")
    for e in errors:
        print(f"  {e}")

if success < 20:
    print("\n*** FATAL: Not enough stego images. Trying without --adaptive --matrix-embedding ***")
    for i in range(NUM_IMAGES):
        cover = COVER_DIR / f"img_{i:04d}.png"
        stego = STEGO_DIR / f"img_{i:04d}.png"
        if stego.exists():
            continue
        try:
            result = subprocess.run(
                [sys.executable, "-m", "stegx", "encode",
                 "-i", str(cover), "-f", str(secret), "-o", str(stego),
                 "--password-stdin"],
                input=b"CnnTestPassword99!",
                capture_output=True, timeout=120
            )
            if result.returncode == 0 and stego.exists():
                success += 1
        except:
            pass
        if (i+1) % 100 == 0:
            print(f"  Fallback: {i+1}/{NUM_IMAGES} (success: {success})")
    print(f"Final count: {success} stego images")

assert success >= 20, f"Only {success} stego images generated. Cannot proceed."

# %% [markdown]
# ## 2. Build SRNet Model

# %%
import torch
import torch.nn as nn
import torch.nn.functional as F


class SRNetType1(nn.Module):
    def __init__(self, in_ch, out_ch):
        super().__init__()
        self.bn1 = nn.BatchNorm2d(in_ch)
        self.conv1 = nn.Conv2d(in_ch, out_ch, 3, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(out_ch)
        self.conv2 = nn.Conv2d(out_ch, out_ch, 3, padding=1, bias=False)

    def forward(self, x):
        out = F.relu(self.bn1(x))
        out = self.conv1(out)
        out = F.relu(self.bn2(out))
        out = self.conv2(out)
        return out + x


class SRNetType2(nn.Module):
    def __init__(self, in_ch, out_ch):
        super().__init__()
        self.bn1 = nn.BatchNorm2d(in_ch)
        self.conv1 = nn.Conv2d(in_ch, out_ch, 3, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(out_ch)
        self.conv2 = nn.Conv2d(out_ch, out_ch, 3, padding=1, bias=False)
        self.shortcut = nn.Conv2d(in_ch, out_ch, 1, bias=False)

    def forward(self, x):
        out = F.relu(self.bn1(x))
        out = self.conv1(out)
        out = F.relu(self.bn2(out))
        out = self.conv2(out)
        return out + self.shortcut(x)


class SRNetType3(nn.Module):
    def __init__(self, in_ch, out_ch):
        super().__init__()
        self.bn1 = nn.BatchNorm2d(in_ch)
        self.conv1 = nn.Conv2d(in_ch, out_ch, 3, padding=1, bias=False)
        self.bn2 = nn.BatchNorm2d(out_ch)
        self.conv2 = nn.Conv2d(out_ch, out_ch, 3, padding=1, bias=False)
        self.shortcut = nn.Conv2d(in_ch, out_ch, 1, bias=False)
        self.pool = nn.AvgPool2d(3, stride=2, padding=1)

    def forward(self, x):
        out = F.relu(self.bn1(x))
        out = self.conv1(out)
        out = F.relu(self.bn2(out))
        out = self.conv2(out)
        out = self.pool(out)
        return out + self.pool(self.shortcut(x))


class SRNet(nn.Module):
    def __init__(self, in_channels=3, num_classes=2):
        super().__init__()
        self.layer0 = nn.Sequential(
            nn.Conv2d(in_channels, 64, 3, padding=1, bias=False),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
        )
        self.layer1 = SRNetType1(64, 64)
        self.layer2 = SRNetType1(64, 64)
        self.layer3 = SRNetType2(64, 128)
        self.layer4 = SRNetType3(128, 128)
        self.layer5 = SRNetType2(128, 256)
        self.layer6 = SRNetType3(256, 256)
        self.layer7 = SRNetType2(256, 512)
        self.layer8 = SRNetType3(512, 512)
        self.global_pool = nn.AdaptiveAvgPool2d(1)
        self.fc = nn.Linear(512, num_classes)

    def forward(self, x):
        x = self.layer0(x)
        x = self.layer1(x)
        x = self.layer2(x)
        x = self.layer3(x)
        x = self.layer4(x)
        x = self.layer5(x)
        x = self.layer6(x)
        x = self.layer7(x)
        x = self.layer8(x)
        x = self.global_pool(x)
        x = x.view(x.size(0), -1)
        return self.fc(x)


print("SRNet model defined successfully")
print(f"Parameters: {sum(p.numel() for p in SRNet().parameters()):,}")

# %% [markdown]
# ## 3. Dataset & DataLoader

# %%
from torch.utils.data import Dataset, DataLoader, random_split
from torchvision import transforms


class StegoDataset(Dataset):
    def __init__(self, cover_dir, stego_dir, transform=None):
        self.transform = transform
        self.samples = []
        
        cover_files = sorted(Path(cover_dir).glob("*.png"))
        stego_files = sorted(Path(stego_dir).glob("*.png"))
        
        stego_names = {f.name for f in stego_files}
        
        for cf in cover_files:
            if cf.name in stego_names:
                self.samples.append((str(cf), 0))
                self.samples.append((str(stego_dir / cf.name), 1))

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        img = Image.open(path).convert("RGB")
        if self.transform:
            img = self.transform(img)
        return img, label


transform = transforms.Compose([
    transforms.RandomCrop(256, pad_if_needed=True),
    transforms.RandomHorizontalFlip(),
    transforms.RandomVerticalFlip(),
    transforms.ToTensor(),
])

dataset = StegoDataset(COVER_DIR, STEGO_DIR, transform=transform)
n_total = len(dataset)
print(f"Total samples: {n_total}")
assert n_total >= 40, f"Need at least 40 samples (20 pairs), got {n_total}"

n_train = int(0.7 * n_total)
n_val = int(0.15 * n_total)
n_test = n_total - n_train - n_val

train_set, val_set, test_set = random_split(
    dataset, [n_train, n_val, n_test],
    generator=torch.Generator().manual_seed(42)
)

train_loader = DataLoader(train_set, batch_size=16, shuffle=True, num_workers=2, pin_memory=True)
val_loader = DataLoader(val_set, batch_size=16, shuffle=False, num_workers=2, pin_memory=True)
test_loader = DataLoader(test_set, batch_size=16, shuffle=False, num_workers=2, pin_memory=True)

print(f"Dataset: {n_total} total ({n_train} train, {n_val} val, {n_test} test)")

# %% [markdown]
# ## 4. Train SRNet

# %%
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Training on: {device}")
if torch.cuda.is_available():
    print(f"GPU: {torch.cuda.get_device_name(0)}")

model = SRNet(in_channels=3, num_classes=2).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=2e-4, weight_decay=1e-5)
scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=25, gamma=0.5)
criterion = nn.CrossEntropyLoss()

EPOCHS = 60
best_val_acc = 0.0
history = {"train_loss": [], "train_acc": [], "val_loss": [], "val_acc": []}

for epoch in range(EPOCHS):
    model.train()
    running_loss, correct, total = 0.0, 0, 0
    
    for imgs, labels in train_loader:
        imgs, labels = imgs.to(device), labels.to(device)
        optimizer.zero_grad()
        outputs = model(imgs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        
        running_loss += loss.item() * imgs.size(0)
        _, preds = outputs.max(1)
        correct += preds.eq(labels).sum().item()
        total += imgs.size(0)
    
    train_loss = running_loss / total
    train_acc = correct / total
    
    model.eval()
    val_loss, val_correct, val_total = 0.0, 0, 0
    with torch.no_grad():
        for imgs, labels in val_loader:
            imgs, labels = imgs.to(device), labels.to(device)
            outputs = model(imgs)
            loss = criterion(outputs, labels)
            val_loss += loss.item() * imgs.size(0)
            _, preds = outputs.max(1)
            val_correct += preds.eq(labels).sum().item()
            val_total += imgs.size(0)
    
    val_loss /= max(val_total, 1)
    val_acc = val_correct / max(val_total, 1)
    
    history["train_loss"].append(train_loss)
    history["train_acc"].append(train_acc)
    history["val_loss"].append(val_loss)
    history["val_acc"].append(val_acc)
    
    scheduler.step()
    
    if val_acc > best_val_acc:
        best_val_acc = val_acc
        torch.save(model.state_dict(), "/content/srnet_best.pth")
    
    if (epoch + 1) % 5 == 0:
        print(f"Epoch {epoch+1:3d}/{EPOCHS} | "
              f"Train Loss: {train_loss:.4f} Acc: {train_acc:.4f} | "
              f"Val Loss: {val_loss:.4f} Acc: {val_acc:.4f}")

print(f"\nBest Validation Accuracy: {best_val_acc:.4f}")

# %% [markdown]
# ## 5. Final Evaluation

# %%
model.load_state_dict(torch.load("/content/srnet_best.pth"))
model.eval()

all_preds, all_labels, all_probs = [], [], []
with torch.no_grad():
    for imgs, labels in test_loader:
        imgs, labels = imgs.to(device), labels.to(device)
        outputs = model(imgs)
        probs = F.softmax(outputs, dim=1)[:, 1]
        _, preds = outputs.max(1)
        all_preds.extend(preds.cpu().numpy())
        all_labels.extend(labels.cpu().numpy())
        all_probs.extend(probs.cpu().numpy())

from sklearn.metrics import accuracy_score, roc_auc_score, confusion_matrix

acc = accuracy_score(all_labels, all_preds)
try:
    auc = roc_auc_score(all_labels, all_probs)
except:
    auc = 0.5
cm = confusion_matrix(all_labels, all_preds)

print("=" * 60)
print("  SRNet STEGANALYSIS RESULTS vs StegX v2.0")
print("=" * 60)
print(f"  Test Accuracy:  {acc:.4f} ({acc*100:.1f}%)")
print(f"  AUC-ROC:        {auc:.4f}")
print(f"  Confusion Matrix:")
print(f"    TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
print(f"    FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")
print()
if acc < 0.55:
    print("  VERDICT: ✅ UNDETECTED")
    print("  SRNet cannot distinguish StegX images from clean images.")
    print("  Detection accuracy is equivalent to random guessing.")
elif acc < 0.65:
    print("  VERDICT: ⚠️ BORDERLINE")
    print("  SRNet shows weak detection capability.")
elif acc < 0.75:
    print("  VERDICT: ⚠️ PARTIALLY DETECTED")
    print("  SRNet can partially distinguish stego images.")
else:
    print("  VERDICT: ❌ DETECTED")
    print("  SRNet can reliably detect StegX images.")
print("=" * 60)

# %%
import matplotlib.pyplot as plt

fig, axes = plt.subplots(1, 2, figsize=(14, 5))

axes[0].plot(history["train_loss"], label="Train Loss")
axes[0].plot(history["val_loss"], label="Val Loss")
axes[0].set_xlabel("Epoch")
axes[0].set_ylabel("Loss")
axes[0].set_title("Training & Validation Loss")
axes[0].legend()
axes[0].axhline(y=0.693, color="r", linestyle="--", alpha=0.5, label="Random (ln2)")

axes[1].plot(history["train_acc"], label="Train Acc")
axes[1].plot(history["val_acc"], label="Val Acc")
axes[1].axhline(y=0.5, color="r", linestyle="--", alpha=0.5, label="Random (50%)")
axes[1].set_xlabel("Epoch")
axes[1].set_ylabel("Accuracy")
axes[1].set_title("Training & Validation Accuracy")
axes[1].legend()

plt.tight_layout()
plt.savefig("/content/srnet_training_curves.png", dpi=150)
plt.show()
print("Training curves saved to /content/srnet_training_curves.png")
