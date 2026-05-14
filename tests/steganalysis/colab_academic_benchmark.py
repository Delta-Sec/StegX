# %% [markdown]
# # Benchmarking Spatial-Domain Steganography Against CNN Steganalysis
# ## A Comparative Study on BOSSBase 1.01
#
# **Dataset:** BOSSBase 1.01 (Bas et al., 2011) — 10,000 real-world grayscale images
# **Detector:** SRNet (Boroumand et al., 2019) — 11.5M parameter CNN
# **Tools:** StegX v2.0, Steghide, Raw LSB Replacement
#
# Runtime: GPU (T4) recommended. Total time: ~3-4 hours.

# %% Step 0 — Install dependencies
import subprocess, sys, os
subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
    "torch", "torchvision", "pillow", "numpy", "scikit-learn",
    "matplotlib", "scipy", "opendatasets", "stegx-cli[compression]"])
print("Dependencies installed.")

# %% Step 1 — Download BOSSBase 1.01
import opendatasets as od
from pathlib import Path
import shutil, glob
from PIL import Image
import numpy as np

WORK = Path("/content/benchmark")
WORK.mkdir(exist_ok=True)
PNG_DIR = WORK / "covers_png"
PNG_DIR.mkdir(exist_ok=True)

existing_pngs = sorted(PNG_DIR.glob("*.png"))
if len(existing_pngs) >= 100:
    print(f"Covers already prepared: {len(existing_pngs)} PNG images")
else:
    print("Downloading BOSSBase 1.01 from Kaggle...")
    od.download("https://www.kaggle.com/datasets/lijiyu/bossbase", data_dir=str(WORK))

    print("\nExploring downloaded structure:")
    for p in sorted(WORK.rglob("*"))[:50]:
        if p.is_file():
            print(f"  FILE: {p} ({p.stat().st_size} bytes)")
        elif p.is_dir():
            print(f"  DIR:  {p}/")

    img_exts = ("*.pgm", "*.png", "*.jpg", "*.jpeg", "*.bmp", "*.tif", "*.tiff")
    all_images = []
    for ext in img_exts:
        found = list(WORK.rglob(ext))
        if found:
            print(f"  Found {len(found)} files matching {ext}")
            all_images.extend(found)

    all_images = [f for f in all_images if PNG_DIR not in f.parents and f.parent != PNG_DIR]
    all_images = sorted(all_images)[:2000]
    print(f"\nTotal source images found: {len(all_images)}")

    if not all_images:
        zips = list(WORK.rglob("*.zip"))
        if zips:
            import zipfile
            for z in zips:
                print(f"  Extracting {z}...")
                with zipfile.ZipFile(str(z), "r") as zf:
                    zf.extractall(str(WORK / "extracted"))
            for ext in img_exts:
                all_images.extend(list((WORK / "extracted").rglob(ext)))
            all_images = sorted(all_images)[:2000]
            print(f"  After extraction: {len(all_images)} images found")

    print(f"\nConverting {len(all_images)} images → RGB PNG...")
    for i, src in enumerate(all_images):
        out = PNG_DIR / f"img_{i:04d}.png"
        if out.exists():
            continue
        try:
            img = Image.open(str(src))
            if img.mode == "L":
                arr = np.array(img)
                rgb = np.stack([arr, arr, arr], axis=-1)
                Image.fromarray(rgb).save(str(out), "PNG")
            elif img.mode == "RGB":
                img.save(str(out), "PNG")
            else:
                img.convert("RGB").save(str(out), "PNG")
        except Exception as e:
            print(f"  Error on {src.name}: {e}")
        if (i+1) % 500 == 0:
            print(f"  {i+1}/{len(all_images)}")

existing_pngs = sorted(PNG_DIR.glob("*.png"))
NUM_IMAGES = len(existing_pngs)
cover_files = existing_pngs[:NUM_IMAGES]
print(f"Ready: {NUM_IMAGES} cover images in {PNG_DIR}")
assert NUM_IMAGES >= 50, f"Only {NUM_IMAGES} images — check Kaggle download"

# %% Step 3 — Generate secret payload
SECRET = WORK / "payload.bin"
if not SECRET.exists():
    with open(SECRET, "wb") as f:
        f.write(os.urandom(200))

# %% Step 4 — Embed with each tool
# --- Tool A: StegX (Adaptive + Matrix) ---
STEGO_STEGX = WORK / "stego_stegx"
STEGO_STEGX.mkdir(exist_ok=True)

print("\n=== Embedding with StegX (adaptive + matrix) ===")
ok = 0
for i, cover in enumerate(cover_files):
    out = STEGO_STEGX / cover.name
    if out.exists(): ok += 1; continue
    r = subprocess.run(
        [sys.executable, "-m", "stegx", "encode",
         "-i", str(cover), "-f", str(SECRET), "-o", str(out),
         "--adaptive", "--matrix-embedding", "--password-stdin"],
        input=b"BenchmarkPass2026!", capture_output=True, timeout=120)
    if r.returncode == 0 and out.exists(): ok += 1
    if (i+1) % 500 == 0: print(f"  {i+1}/{NUM_IMAGES} (ok={ok})")
print(f"StegX: {ok}/{NUM_IMAGES} images embedded")

# --- Tool B: Steghide (via BMP intermediary) ---
STEGO_STEGHIDE = WORK / "stego_steghide"
STEGO_STEGHIDE.mkdir(exist_ok=True)

subprocess.run(["apt-get", "install", "-qq", "-y", "steghide"],
               capture_output=True)

print("\n=== Embedding with Steghide ===")
ok2 = 0
for i, cover in enumerate(cover_files):
    out_png = STEGO_STEGHIDE / cover.name
    if out_png.exists(): ok2 += 1; continue
    bmp_in = WORK / "tmp_cover.bmp"
    bmp_out = WORK / "tmp_stego.bmp"
    try:
        Image.open(str(cover)).save(str(bmp_in), "BMP")
        shutil.copy2(str(bmp_in), str(bmp_out))
        r = subprocess.run(
            ["steghide", "embed", "-cf", str(bmp_out), "-ef", str(SECRET),
             "-p", "BenchmarkPass2026!", "-f"],
            capture_output=True, timeout=30)
        if r.returncode == 0:
            Image.open(str(bmp_out)).save(str(out_png), "PNG")
            ok2 += 1
    except Exception:
        pass
    finally:
        bmp_in.unlink(missing_ok=True)
        bmp_out.unlink(missing_ok=True)
    if (i+1) % 500 == 0: print(f"  {i+1}/{NUM_IMAGES} (ok={ok2})")
print(f"Steghide: {ok2}/{NUM_IMAGES} images embedded")

# --- Tool C: Raw LSB Replacement (naive baseline) ---
STEGO_RAW = WORK / "stego_rawlsb"
STEGO_RAW.mkdir(exist_ok=True)

print("\n=== Embedding with Raw LSB Replacement (baseline) ===")

def raw_lsb_embed(cover_path, output_path, data_bytes):
    img = np.array(Image.open(str(cover_path)))
    flat = img.flatten().copy()
    bits = []
    for b in data_bytes:
        for bit_pos in range(8):
            bits.append((b >> (7 - bit_pos)) & 1)
    for j, bit in enumerate(bits):
        if j >= len(flat): break
        flat[j] = (flat[j] & 0xFE) | bit
    img_out = flat.reshape(img.shape)
    Image.fromarray(img_out.astype(np.uint8)).save(str(output_path), "PNG")

payload_bytes = open(SECRET, "rb").read()
ok3 = 0
for i, cover in enumerate(cover_files):
    out = STEGO_RAW / cover.name
    if out.exists(): ok3 += 1; continue
    try:
        raw_lsb_embed(cover, out, payload_bytes)
        ok3 += 1
    except Exception:
        pass
    if (i+1) % 500 == 0: print(f"  {i+1}/{NUM_IMAGES} (ok={ok3})")
print(f"Raw LSB: {ok3}/{NUM_IMAGES} images embedded")

# %% Step 5 — Statistical Metrics (per tool)
from scipy import stats as sp_stats
import json

def compute_metrics(cover_path, stego_path):
    c = np.array(Image.open(str(cover_path)), dtype=np.float64)
    s = np.array(Image.open(str(stego_path)), dtype=np.float64)
    mse = np.mean((c - s) ** 2)
    psnr = 10 * np.log10(255**2 / mse) if mse > 0 else float("inf")
    C1, C2 = (0.01*255)**2, (0.03*255)**2
    mu_c, mu_s = np.mean(c), np.mean(s)
    sc, ss = np.var(c), np.var(s)
    scs = np.mean((c - mu_c) * (s - mu_s))
    ssim = ((2*mu_c*mu_s+C1)*(2*scs+C2)) / ((mu_c**2+mu_s**2+C1)*(sc+ss+C2))
    kl_vals = []
    for ch in range(c.shape[2]):
        hc = np.histogram(c[:,:,ch].flatten(), 256, (0,256))[0].astype(float)
        hs = np.histogram(s[:,:,ch].flatten(), 256, (0,256))[0].astype(float)
        hc = (hc+1)/(hc.sum()+256)
        hs = (hs+1)/(hs.sum()+256)
        kl_vals.append(sp_stats.entropy(hc, hs))
    return {"psnr": psnr, "ssim": float(ssim), "kl": float(np.mean(kl_vals))}

tools = {
    "StegX": STEGO_STEGX,
    "Steghide": STEGO_STEGHIDE,
    "Raw LSB": STEGO_RAW,
}

N_METRIC = 200
print(f"\n=== Computing PSNR/SSIM/KL on {N_METRIC} images per tool ===")
metric_results = {}
for name, sdir in tools.items():
    psnrs, ssims, kls = [], [], []
    for cover in cover_files[:N_METRIC]:
        stego = sdir / cover.name
        if not stego.exists(): continue
        m = compute_metrics(cover, stego)
        psnrs.append(m["psnr"]); ssims.append(m["ssim"]); kls.append(m["kl"])
    metric_results[name] = {
        "psnr_mean": f"{np.mean(psnrs):.2f}" if psnrs else "N/A",
        "ssim_mean": f"{np.mean(ssims):.6f}" if ssims else "N/A",
        "kl_mean": f"{np.mean(kls):.8f}" if kls else "N/A",
        "n": len(psnrs)
    }
    print(f"  {name}: PSNR={metric_results[name]['psnr_mean']} dB | "
          f"SSIM={metric_results[name]['ssim_mean']} | "
          f"KL={metric_results[name]['kl_mean']}")

# %% Step 6 — Build SRNet
import torch
import torch.nn as nn
import torch.nn.functional as F

class SRNetBlock1(nn.Module):
    def __init__(self, ch):
        super().__init__()
        self.bn1=nn.BatchNorm2d(ch); self.c1=nn.Conv2d(ch,ch,3,1,1,bias=False)
        self.bn2=nn.BatchNorm2d(ch); self.c2=nn.Conv2d(ch,ch,3,1,1,bias=False)
    def forward(self,x):
        o=self.c1(F.relu(self.bn1(x))); o=self.c2(F.relu(self.bn2(o))); return o+x

class SRNetBlock2(nn.Module):
    def __init__(self,ci,co):
        super().__init__()
        self.bn1=nn.BatchNorm2d(ci); self.c1=nn.Conv2d(ci,co,3,1,1,bias=False)
        self.bn2=nn.BatchNorm2d(co); self.c2=nn.Conv2d(co,co,3,1,1,bias=False)
        self.sc=nn.Conv2d(ci,co,1,bias=False)
    def forward(self,x):
        o=self.c1(F.relu(self.bn1(x))); o=self.c2(F.relu(self.bn2(o)))
        return o+self.sc(x)

class SRNetBlock3(nn.Module):
    def __init__(self,ci,co):
        super().__init__()
        self.bn1=nn.BatchNorm2d(ci); self.c1=nn.Conv2d(ci,co,3,1,1,bias=False)
        self.bn2=nn.BatchNorm2d(co); self.c2=nn.Conv2d(co,co,3,1,1,bias=False)
        self.sc=nn.Conv2d(ci,co,1,bias=False)
        self.pool=nn.AvgPool2d(3,2,1)
    def forward(self,x):
        o=self.c1(F.relu(self.bn1(x))); o=self.c2(F.relu(self.bn2(o)))
        return self.pool(o)+self.pool(self.sc(x))

class SRNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.l0=nn.Sequential(nn.Conv2d(3,64,3,1,1,bias=False),nn.BatchNorm2d(64),nn.ReLU(True))
        self.l1=SRNetBlock1(64); self.l2=SRNetBlock1(64)
        self.l3=SRNetBlock2(64,128); self.l4=SRNetBlock3(128,128)
        self.l5=SRNetBlock2(128,256); self.l6=SRNetBlock3(256,256)
        self.l7=SRNetBlock2(256,512); self.l8=SRNetBlock3(512,512)
        self.gap=nn.AdaptiveAvgPool2d(1); self.fc=nn.Linear(512,2)
    def forward(self,x):
        x=self.l0(x)
        x=self.l1(x);x=self.l2(x);x=self.l3(x);x=self.l4(x)
        x=self.l5(x);x=self.l6(x);x=self.l7(x);x=self.l8(x)
        return self.fc(self.gap(x).view(x.size(0),-1))

print(f"SRNet: {sum(p.numel() for p in SRNet().parameters()):,} parameters")

# %% Step 7 — Dataset + DataLoader (image-level split, no leakage)
from torch.utils.data import Dataset, DataLoader, Subset
from torchvision import transforms

class PairedStegoDataset(Dataset):
    def __init__(self, cover_dir, stego_dir, transform=None):
        self.transform = transform
        self.samples = []
        self.pairs = []
        covers = sorted(Path(cover_dir).glob("*.png"))
        stegos = {f.name for f in Path(stego_dir).glob("*.png")}
        pid = 0
        for cf in covers:
            if cf.name in stegos:
                self.samples.append((str(cf), 0, pid))
                self.samples.append((str(stego_dir / cf.name), 1, pid))
                self.pairs.append(pid); pid += 1
    def __len__(self): return len(self.samples)
    def __getitem__(self, idx):
        p, l, _ = self.samples[idx]
        img = Image.open(p).convert("RGB")
        if self.transform: img = self.transform(img)
        return img, l

def make_loaders(cover_dir, stego_dir, batch_size=16):
    tf_train = transforms.Compose([
        transforms.RandomCrop(256,pad_if_needed=True),
        transforms.RandomHorizontalFlip(), transforms.RandomVerticalFlip(),
        transforms.ToTensor()])
    tf_test = transforms.Compose([transforms.CenterCrop(256), transforms.ToTensor()])

    ds = PairedStegoDataset(cover_dir, stego_dir, tf_train)
    np_pairs = len(ds.pairs)
    rng = np.random.RandomState(42)
    idx = rng.permutation(np_pairs)
    nt = int(0.7*np_pairs); nv = int(0.15*np_pairs)
    tr_set = set(idx[:nt]); va_set = set(idx[nt:nt+nv]); te_set = set(idx[nt+nv:])

    tr_i = [i for i,(_, _, p) in enumerate(ds.samples) if p in tr_set]
    va_i = [i for i,(_, _, p) in enumerate(ds.samples) if p in va_set]
    te_i = [i for i,(_, _, p) in enumerate(ds.samples) if p in te_set]

    ds_te = PairedStegoDataset(cover_dir, stego_dir, tf_test)
    pin = torch.cuda.is_available()
    return (DataLoader(Subset(ds,tr_i), batch_size, shuffle=True, num_workers=2, pin_memory=pin),
            DataLoader(Subset(ds,va_i), batch_size, num_workers=2, pin_memory=pin),
            DataLoader(Subset(ds_te,te_i), batch_size, num_workers=2, pin_memory=pin),
            {"train":len(tr_i),"val":len(va_i),"test":len(te_i),
             "pairs":np_pairs,"leak":len(tr_set&te_set)})

# %% Step 8 — Train + Evaluate SRNet per tool
from sklearn.metrics import accuracy_score, roc_auc_score, confusion_matrix

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {device}")
if torch.cuda.is_available(): print(f"GPU: {torch.cuda.get_device_name(0)}")

EPOCHS = 50
all_results = {}

for tool_name, stego_dir in tools.items():
    n_stego = len(list(stego_dir.glob("*.png")))
    if n_stego < 50:
        print(f"\n*** Skipping {tool_name}: only {n_stego} stego images ***")
        continue

    print(f"\n{'='*60}")
    print(f"  TRAINING SRNet vs {tool_name} ({n_stego} stego images)")
    print(f"{'='*60}")

    train_ld, val_ld, test_ld, info = make_loaders(PNG_DIR, stego_dir)
    print(f"  Split: {info} | Leak: {info['leak']} (must be 0)")

    model = SRNet().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=2e-4, weight_decay=1e-5)
    sched = torch.optim.lr_scheduler.StepLR(opt, 20, 0.5)
    crit = nn.CrossEntropyLoss()
    hist = {"tl":[],"ta":[],"vl":[],"va":[]}
    best_va = 0.0

    for ep in range(EPOCHS):
        model.train()
        rl, co, to = 0., 0, 0
        for imgs, labs in train_ld:
            imgs, labs = imgs.to(device), labs.to(device)
            opt.zero_grad(); out = model(imgs)
            loss = crit(out, labs); loss.backward(); opt.step()
            rl += loss.item()*imgs.size(0)
            co += out.max(1)[1].eq(labs).sum().item(); to += imgs.size(0)
        tl, ta = rl/to, co/to

        model.eval(); vl, vc, vt = 0., 0, 0
        with torch.no_grad():
            for imgs, labs in val_ld:
                imgs, labs = imgs.to(device), labs.to(device)
                out = model(imgs); loss = crit(out, labs)
                vl += loss.item()*imgs.size(0)
                vc += out.max(1)[1].eq(labs).sum().item(); vt += imgs.size(0)
        vl /= max(vt,1); va = vc/max(vt,1)
        hist["tl"].append(tl);hist["ta"].append(ta);hist["vl"].append(vl);hist["va"].append(va)
        sched.step()
        if va > best_va:
            best_va = va
            torch.save(model.state_dict(), f"/content/srnet_{tool_name.replace(' ','_')}.pth")
        if (ep+1)%10==0:
            print(f"  Epoch {ep+1:3d} | TrLoss {tl:.4f} TrAcc {ta:.4f} | VaLoss {vl:.4f} VaAcc {va:.4f}")

    model.load_state_dict(torch.load(f"/content/srnet_{tool_name.replace(' ','_')}.pth"))
    model.eval()
    preds, labels, probs = [],[],[]
    with torch.no_grad():
        for imgs, labs in test_ld:
            imgs, labs = imgs.to(device), labs.to(device)
            out = model(imgs); pr = F.softmax(out,1)[:,1]
            preds.extend(out.max(1)[1].cpu().numpy())
            labels.extend(labs.cpu().numpy())
            probs.extend(pr.cpu().numpy())

    acc = accuracy_score(labels, preds)
    try: auc = roc_auc_score(labels, probs)
    except: auc = 0.5
    cm = confusion_matrix(labels, preds)

    all_results[tool_name] = {
        "accuracy": acc, "auc": auc, "cm": cm.tolist(),
        "best_val_acc": best_va, "history": hist,
        "metrics": metric_results.get(tool_name, {}),
        "info": info
    }

    print(f"\n  {tool_name} RESULTS:")
    print(f"  Test Accuracy: {acc:.4f} ({acc*100:.1f}%)")
    print(f"  AUC-ROC:       {auc:.4f}")
    print(f"  Confusion:     TN={cm[0][0]} FP={cm[0][1]} FN={cm[1][0]} TP={cm[1][1]}")
    verdict = "UNDETECTED" if acc<0.55 else "BORDERLINE" if acc<0.65 else "PARTIALLY DETECTED" if acc<0.75 else "DETECTED"
    print(f"  Verdict:       {verdict}")

# %% Step 9 — Comparative Summary Table
print("\n" + "="*75)
print("  COMPARATIVE STEGANALYSIS BENCHMARK — BOSSBase 1.01 + SRNet")
print("="*75)
header = f"{'Tool':<18} {'Accuracy':<12} {'AUC-ROC':<10} {'PSNR (dB)':<12} {'SSIM':<12} {'Verdict':<15}"
print(header)
print("-"*len(header))
for name, r in all_results.items():
    acc = r["accuracy"]
    verdict = "UNDETECTED" if acc<0.55 else "BORDERLINE" if acc<0.65 else "PARTIAL" if acc<0.75 else "DETECTED"
    m = r.get("metrics",{})
    print(f"{name:<18} {acc*100:>5.1f}%      {r['auc']:.4f}     "
          f"{m.get('psnr_mean','N/A'):<12} {m.get('ssim_mean','N/A'):<12} {verdict}")
print("="*len(header))
print("\nRandom guessing baseline = 50.0% accuracy / 0.500 AUC")

# %% Step 10 — Publication-quality plots
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams.update({"font.size":11, "font.family":"serif"})

fig, axes = plt.subplots(1, 3, figsize=(18, 5))

names = list(all_results.keys())
accs = [all_results[n]["accuracy"]*100 for n in names]
aucs = [all_results[n]["auc"] for n in names]
colors = ["#2ecc71" if a<55 else "#e67e22" if a<65 else "#e74c3c" for a in accs]

axes[0].barh(names, accs, color=colors, edgecolor="black", linewidth=0.5)
axes[0].axvline(x=50, color="red", linestyle="--", alpha=0.7, label="Random (50%)")
axes[0].set_xlabel("Detection Accuracy (%)")
axes[0].set_title("SRNet Detection Accuracy per Tool")
axes[0].set_xlim(0, 105)
axes[0].legend()
for i, v in enumerate(accs):
    axes[0].text(v+1, i, f"{v:.1f}%", va="center", fontweight="bold")

axes[1].barh(names, aucs, color=colors, edgecolor="black", linewidth=0.5)
axes[1].axvline(x=0.5, color="red", linestyle="--", alpha=0.7, label="Random (0.5)")
axes[1].set_xlabel("AUC-ROC")
axes[1].set_title("SRNet AUC-ROC per Tool")
axes[1].set_xlim(0, 1.05)
axes[1].legend()

for n in names:
    h = all_results[n]["history"]
    axes[2].plot(h["va"], label=f"{n}")
axes[2].axhline(y=0.5, color="red", linestyle="--", alpha=0.5, label="Random")
axes[2].set_xlabel("Epoch")
axes[2].set_ylabel("Validation Accuracy")
axes[2].set_title("SRNet Training Curves")
axes[2].legend()
axes[2].set_ylim(0.3, 1.05)

plt.tight_layout()
plt.savefig("/content/benchmark_results.png", dpi=300, bbox_inches="tight")
plt.show()
print("Plot saved: /content/benchmark_results.png")

# %% Step 11 — Save full results as JSON
results_export = {}
for n, r in all_results.items():
    results_export[n] = {
        "test_accuracy": f"{r['accuracy']:.4f}",
        "auc_roc": f"{r['auc']:.4f}",
        "best_val_accuracy": f"{r['best_val_acc']:.4f}",
        "confusion_matrix": r["cm"],
        "metrics": r.get("metrics", {}),
        "dataset": "BOSSBase 1.01",
        "images": r["info"]["pairs"],
        "split": r["info"],
        "detector": "SRNet (11.5M params)",
        "epochs": EPOCHS,
    }

with open("/content/benchmark_results.json", "w") as f:
    json.dump(results_export, f, indent=2)
print("Results saved: /content/benchmark_results.json")

print("\n" + "="*60)
print("  BENCHMARK COMPLETE")
print("="*60)
