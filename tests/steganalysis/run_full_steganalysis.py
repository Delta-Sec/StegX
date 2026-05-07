"""
StegX v2.0 — Comprehensive Steganalysis Resistance Test Suite
==============================================================
Tests:
  1. Chi-Square (X2) Analysis
  2. RS Analysis (Regular-Singular groups)
  3. Sample Pair Analysis (SPA)
  4. Histogram Analysis
  5. Entropy Deviation
  6. PSNR (Peak Signal-to-Noise Ratio)
  7. SSIM (Structural Similarity Index)
  8. KL Divergence
  9. ML Classifier (SRM-like features + Random Forest)

Usage:
  python run_full_steganalysis.py [--images-dir DIR] [--num-images N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from PIL import Image, ImageDraw, ImageFilter
from scipy import stats as scipy_stats
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report
from sklearn.model_selection import cross_val_score, StratifiedKFold


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent
RESULTS_DIR = SCRIPT_DIR / "results"
DATASET_DIR = SCRIPT_DIR / "dataset"


def generate_test_images(n: int = 50, size: Tuple[int, int] = (512, 512)) -> List[Path]:
    cover_dir = DATASET_DIR / "covers"
    cover_dir.mkdir(parents=True, exist_ok=True)

    paths = []
    for i in range(n):
        img_path = cover_dir / f"cover_{i:03d}.png"
        if img_path.exists():
            paths.append(img_path)
            continue

        rng = np.random.RandomState(seed=i + 42)
        base = rng.randint(60, 200, size=(*size, 3), dtype=np.uint8)
        img = Image.fromarray(base, "RGB")

        draw = ImageDraw.Draw(img)
        for _ in range(rng.randint(5, 20)):
            x0, y0 = rng.randint(0, size[0] - 50), rng.randint(0, size[1] - 50)
            x1, y1 = x0 + rng.randint(20, 100), y0 + rng.randint(20, 100)
            color = tuple(rng.randint(0, 255, 3).tolist())
            draw.rectangle([x0, y0, x1, y1], fill=color)

        for _ in range(rng.randint(3, 10)):
            cx, cy = rng.randint(0, size[0]), rng.randint(0, size[1])
            r = rng.randint(10, 60)
            color = tuple(rng.randint(0, 255, 3).tolist())
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)

        img = img.filter(ImageFilter.GaussianBlur(radius=rng.uniform(0.5, 2.0)))

        noise = rng.randint(-3, 4, size=(*size, 3), dtype=np.int16)
        arr = np.clip(np.array(img, dtype=np.int16) + noise, 0, 255).astype(np.uint8)
        img = Image.fromarray(arr, "RGB")

        img.save(str(img_path), "PNG")
        paths.append(img_path)

    return paths


def generate_stego_images(cover_paths: List[Path], mode: str) -> List[Path]:
    stego_dir = DATASET_DIR / f"stego_{mode}"
    stego_dir.mkdir(parents=True, exist_ok=True)

    secret_file = DATASET_DIR / "secret_payload.bin"
    if not secret_file.exists():
        DATASET_DIR.mkdir(parents=True, exist_ok=True)
        with open(secret_file, "wb") as f:
            f.write(os.urandom(512))

    stego_paths = []
    for cover_path in cover_paths:
        stego_path = stego_dir / cover_path.name
        if stego_path.exists():
            stego_paths.append(stego_path)
            continue

        cmd = [
            sys.executable, "-m", "stegx", "encode",
            "-i", str(cover_path),
            "-f", str(secret_file),
            "-o", str(stego_path),
            "--password-stdin",
        ]

        if mode == "adaptive":
            cmd.append("--adaptive")
        elif mode == "matrix":
            cmd.extend(["--matrix-embedding"])
        elif mode == "adaptive_matrix":
            cmd.extend(["--adaptive", "--matrix-embedding"])
        elif mode == "extreme":
            cmd.extend(["--adaptive", "--matrix-embedding", "--adaptive-mode", "hill"])

        try:
            result = subprocess.run(
                cmd,
                input=b"TestPassword123!",
                capture_output=True,
                timeout=60,
                cwd=str(PROJECT_ROOT),
            )
            if result.returncode == 0 and stego_path.exists():
                stego_paths.append(stego_path)
            else:
                stderr = result.stderr.decode(errors="replace")
                if "capacity" in stderr.lower() or "too large" in stderr.lower():
                    pass
        except Exception:
            pass

    return stego_paths


def load_image_array(path: Path) -> np.ndarray:
    return np.array(Image.open(str(path)).convert("RGB"), dtype=np.float64)


def chi_square_test(image: np.ndarray) -> float:
    scores = []
    for ch in range(image.shape[2]):
        channel = image[:, :, ch].astype(int).flatten()
        chi2 = 0.0
        for v in range(0, 255, 2):
            n_even = np.sum(channel == v)
            n_odd = np.sum(channel == (v + 1))
            total = n_even + n_odd
            if total > 0:
                expected = total / 2.0
                chi2 += (n_even - expected) ** 2 / expected
                chi2 += (n_odd - expected) ** 2 / expected
        df = 127
        p_value = 1.0 - scipy_stats.chi2.cdf(chi2, df)
        scores.append(p_value)
    return float(np.mean(scores))


def rs_analysis(image: np.ndarray) -> float:
    results = []
    for ch in range(image.shape[2]):
        channel = image[:, :, ch].astype(int)
        h, w = channel.shape

        r_p, s_p, r_n, s_n = 0, 0, 0, 0
        block_size = 4

        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = channel[y:y + block_size, x:x + block_size].flatten()

                smoothness_orig = np.sum(np.abs(np.diff(block)))

                flipped_p = block.copy()
                flipped_p[::2] = flipped_p[::2] ^ 1
                smoothness_p = np.sum(np.abs(np.diff(flipped_p)))

                flipped_n = block.copy()
                flipped_n[1::2] = flipped_n[1::2] ^ 1
                smoothness_n = np.sum(np.abs(np.diff(flipped_n)))

                if smoothness_p > smoothness_orig:
                    r_p += 1
                elif smoothness_p < smoothness_orig:
                    s_p += 1

                if smoothness_n > smoothness_orig:
                    r_n += 1
                elif smoothness_n < smoothness_orig:
                    s_n += 1

        total = max(r_p + s_p + r_n + s_n, 1)
        rs_ratio = abs(r_p - s_p) / total + abs(r_n - s_n) / total
        results.append(rs_ratio)

    return float(np.mean(results))


def sample_pair_analysis(image: np.ndarray) -> float:
    results = []
    for ch in range(image.shape[2]):
        channel = image[:, :, ch].astype(int).flatten()
        n = len(channel) - 1

        close_pairs = 0
        for i in range(0, n, 2):
            if abs(channel[i] - channel[i + 1]) <= 1:
                close_pairs += 1

        ratio = close_pairs / (n // 2)
        results.append(ratio)

    return float(np.mean(results))


def histogram_analysis(image: np.ndarray) -> Dict[str, float]:
    flatness_scores = []
    pov_scores = []

    for ch in range(image.shape[2]):
        channel = image[:, :, ch].astype(int).flatten()
        hist = np.histogram(channel, bins=256, range=(0, 256))[0].astype(float)

        hist_norm = hist / hist.sum()
        uniform = np.ones(256) / 256
        kl = scipy_stats.entropy(hist_norm + 1e-10, uniform + 1e-10)
        flatness_scores.append(kl)

        pov = 0.0
        for v in range(0, 255, 2):
            total = hist[v] + hist[v + 1]
            if total > 0:
                pov += abs(hist[v] - hist[v + 1]) / total
        pov /= 128
        pov_scores.append(pov)

    return {
        "kl_from_uniform": float(np.mean(flatness_scores)),
        "pov_asymmetry": float(np.mean(pov_scores)),
    }


def entropy_analysis(image: np.ndarray) -> float:
    entropies = []
    for ch in range(image.shape[2]):
        channel = image[:, :, ch].astype(int).flatten()
        hist = np.histogram(channel, bins=256, range=(0, 256))[0].astype(float)
        hist = hist / hist.sum()
        hist = hist[hist > 0]
        entropy = -np.sum(hist * np.log2(hist))
        entropies.append(entropy)
    return float(np.mean(entropies))


def compute_psnr(cover: np.ndarray, stego: np.ndarray) -> float:
    mse = np.mean((cover - stego) ** 2)
    if mse == 0:
        return float("inf")
    return 10.0 * math.log10(255.0 ** 2 / mse)


def compute_ssim(cover: np.ndarray, stego: np.ndarray) -> float:
    C1 = (0.01 * 255) ** 2
    C2 = (0.03 * 255) ** 2

    mu_x = np.mean(cover)
    mu_y = np.mean(stego)
    sigma_x2 = np.var(cover)
    sigma_y2 = np.var(stego)
    sigma_xy = np.mean((cover - mu_x) * (stego - mu_y))

    ssim = ((2 * mu_x * mu_y + C1) * (2 * sigma_xy + C2)) / \
           ((mu_x ** 2 + mu_y ** 2 + C1) * (sigma_x2 + sigma_y2 + C2))
    return float(ssim)


def compute_kl_divergence(cover: np.ndarray, stego: np.ndarray) -> float:
    kl_values = []
    for ch in range(cover.shape[2]):
        hist_c = np.histogram(cover[:, :, ch].flatten(), bins=256, range=(0, 256))[0].astype(float)
        hist_s = np.histogram(stego[:, :, ch].flatten(), bins=256, range=(0, 256))[0].astype(float)
        hist_c = (hist_c + 1) / (hist_c.sum() + 256)
        hist_s = (hist_s + 1) / (hist_s.sum() + 256)
        kl = scipy_stats.entropy(hist_c, hist_s)
        kl_values.append(kl)
    return float(np.mean(kl_values))


def extract_srm_features(image: np.ndarray) -> np.ndarray:
    features = []

    for ch in range(min(image.shape[2], 3)):
        channel = image[:, :, ch]

        residual_h = np.diff(channel, axis=1)
        residual_v = np.diff(channel, axis=0)

        hist_h = np.histogram(residual_h.flatten(), bins=np.arange(-5, 7))[0].astype(float)
        hist_h /= max(hist_h.sum(), 1)
        features.extend(hist_h.tolist())

        hist_v = np.histogram(residual_v.flatten(), bins=np.arange(-5, 7))[0].astype(float)
        hist_v /= max(hist_v.sum(), 1)
        features.extend(hist_v.tolist())

        hist_2nd_h = np.histogram(np.diff(channel, n=2, axis=1).flatten(), bins=np.arange(-8, 10))[0].astype(float)
        hist_2nd_h /= max(hist_2nd_h.sum(), 1)
        features.extend(hist_2nd_h.tolist())

        hist_2nd_v = np.histogram(np.diff(channel, n=2, axis=0).flatten(), bins=np.arange(-8, 10))[0].astype(float)
        hist_2nd_v /= max(hist_2nd_v.sum(), 1)
        features.extend(hist_2nd_v.tolist())

        kernel = np.array([[-1, 2, -1], [2, -4, 2], [-1, 2, -1]], dtype=np.float64)
        from scipy.ndimage import convolve
        lap = convolve(channel, kernel, mode="reflect")
        hist_lap = np.histogram(lap.flatten(), bins=np.arange(-10, 12))[0].astype(float)
        hist_lap /= max(hist_lap.sum(), 1)
        features.extend(hist_lap.tolist())

        lsb = (channel.astype(int) % 2).flatten()
        features.append(float(np.mean(lsb)))
        features.append(float(np.std(lsb)))

        pairs = channel.astype(int).flatten()
        even_odd_ratio = []
        for v in range(0, 254, 2):
            n_e = np.sum(pairs == v)
            n_o = np.sum(pairs == (v + 1))
            if n_e + n_o > 10:
                even_odd_ratio.append(abs(n_e - n_o) / (n_e + n_o))
        features.append(float(np.mean(even_odd_ratio)) if even_odd_ratio else 0.0)
        features.append(float(np.std(even_odd_ratio)) if even_odd_ratio else 0.0)

        hist = np.histogram(channel.flatten(), bins=256, range=(0, 256))[0].astype(float)
        hist_norm = hist / hist.sum()
        entropy = -np.sum(hist_norm[hist_norm > 0] * np.log2(hist_norm[hist_norm > 0]))
        features.append(entropy)

    return np.array(features, dtype=np.float64)


def run_ml_classifier(cover_paths: List[Path], stego_paths: List[Path]) -> Dict:
    n = min(len(cover_paths), len(stego_paths))
    if n < 10:
        return {"error": "Not enough images for ML classification (need >= 10 pairs)"}

    print(f"  Extracting SRM features from {n} cover + {n} stego images...")
    X = []
    y = []

    for p in cover_paths[:n]:
        img = load_image_array(p)
        feat = extract_srm_features(img)
        X.append(feat)
        y.append(0)

    for p in stego_paths[:n]:
        img = load_image_array(p)
        feat = extract_srm_features(img)
        X.append(feat)
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    nan_mask = np.isnan(X) | np.isinf(X)
    X[nan_mask] = 0.0

    n_splits = min(5, n)
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    rf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
    rf_scores = cross_val_score(rf, X, y, cv=cv, scoring="accuracy")

    gb = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
    gb_scores = cross_val_score(gb, X, y, cv=cv, scoring="accuracy")

    rf.fit(X, y)
    rf_probs = rf.predict_proba(X)[:, 1]
    try:
        rf_auc = roc_auc_score(y, rf_probs)
    except ValueError:
        rf_auc = 0.5

    gb.fit(X, y)
    gb_probs = gb.predict_proba(X)[:, 1]
    try:
        gb_auc = roc_auc_score(y, gb_probs)
    except ValueError:
        gb_auc = 0.5

    importances = rf.feature_importances_
    top_features = np.argsort(importances)[-5:][::-1]

    return {
        "random_forest_cv_accuracy": f"{rf_scores.mean():.4f} +/- {rf_scores.std():.4f}",
        "gradient_boosting_cv_accuracy": f"{gb_scores.mean():.4f} +/- {gb_scores.std():.4f}",
        "random_forest_auc_roc": f"{rf_auc:.4f}",
        "gradient_boosting_auc_roc": f"{gb_auc:.4f}",
        "top_discriminative_features": top_features.tolist(),
        "verdict": "UNDETECTED" if rf_scores.mean() < 0.60 else "BORDERLINE" if rf_scores.mean() < 0.75 else "DETECTED",
    }


def run_full_analysis(cover_paths: List[Path], stego_paths: List[Path], mode: str) -> Dict:
    n = min(len(cover_paths), len(stego_paths))
    if n == 0:
        return {"error": f"No stego images generated for mode: {mode}"}

    print(f"\n{'=' * 60}")
    print(f"  ANALYZING MODE: {mode.upper()} ({n} image pairs)")
    print(f"{'=' * 60}")

    chi2_cover, chi2_stego = [], []
    rs_cover, rs_stego = [], []
    spa_cover, spa_stego = [], []
    hist_cover, hist_stego = [], []
    entropy_cover, entropy_stego = [], []
    psnr_vals, ssim_vals, kl_vals = [], [], []

    for i in range(n):
        cover = load_image_array(cover_paths[i])
        stego = load_image_array(stego_paths[i])

        chi2_cover.append(chi_square_test(cover))
        chi2_stego.append(chi_square_test(stego))

        rs_cover.append(rs_analysis(cover))
        rs_stego.append(rs_analysis(stego))

        spa_cover.append(sample_pair_analysis(cover))
        spa_stego.append(sample_pair_analysis(stego))

        hc = histogram_analysis(cover)
        hs = histogram_analysis(stego)
        hist_cover.append(hc)
        hist_stego.append(hs)

        entropy_cover.append(entropy_analysis(cover))
        entropy_stego.append(entropy_analysis(stego))

        psnr_vals.append(compute_psnr(cover, stego))
        ssim_vals.append(compute_ssim(cover, stego))
        kl_vals.append(compute_kl_divergence(cover, stego))

        if (i + 1) % 10 == 0:
            print(f"  Processed {i + 1}/{n} images...")

    chi2_p = scipy_stats.mannwhitneyu(chi2_cover, chi2_stego, alternative="two-sided").pvalue
    rs_p = scipy_stats.mannwhitneyu(rs_cover, rs_stego, alternative="two-sided").pvalue
    spa_p = scipy_stats.mannwhitneyu(spa_cover, spa_stego, alternative="two-sided").pvalue

    print(f"\n  Running ML classifier (SRM features)...")
    ml_results = run_ml_classifier(cover_paths[:n], stego_paths[:n])

    results = {
        "mode": mode,
        "num_images": n,
        "chi_square": {
            "cover_mean_p": f"{np.mean(chi2_cover):.6f}",
            "stego_mean_p": f"{np.mean(chi2_stego):.6f}",
            "mann_whitney_p": f"{chi2_p:.6f}",
            "verdict": "UNDETECTED" if chi2_p > 0.05 else "DETECTED",
        },
        "rs_analysis": {
            "cover_mean": f"{np.mean(rs_cover):.6f}",
            "stego_mean": f"{np.mean(rs_stego):.6f}",
            "mann_whitney_p": f"{rs_p:.6f}",
            "verdict": "UNDETECTED" if rs_p > 0.05 else "DETECTED",
        },
        "sample_pair": {
            "cover_mean": f"{np.mean(spa_cover):.6f}",
            "stego_mean": f"{np.mean(spa_stego):.6f}",
            "mann_whitney_p": f"{spa_p:.6f}",
            "verdict": "UNDETECTED" if spa_p > 0.05 else "DETECTED",
        },
        "histogram": {
            "cover_pov": f"{np.mean([h['pov_asymmetry'] for h in hist_cover]):.6f}",
            "stego_pov": f"{np.mean([h['pov_asymmetry'] for h in hist_stego]):.6f}",
            "cover_kl": f"{np.mean([h['kl_from_uniform'] for h in hist_cover]):.6f}",
            "stego_kl": f"{np.mean([h['kl_from_uniform'] for h in hist_stego]):.6f}",
        },
        "entropy": {
            "cover_mean": f"{np.mean(entropy_cover):.4f}",
            "stego_mean": f"{np.mean(entropy_stego):.4f}",
            "delta": f"{abs(np.mean(entropy_stego) - np.mean(entropy_cover)):.6f}",
            "verdict": "UNDETECTED" if abs(np.mean(entropy_stego) - np.mean(entropy_cover)) < 0.01 else "DETECTED",
        },
        "psnr": {
            "mean_dB": f"{np.mean(psnr_vals):.2f}",
            "min_dB": f"{np.min(psnr_vals):.2f}",
            "verdict": "IMPERCEPTIBLE" if np.mean(psnr_vals) > 50 else "VISIBLE",
        },
        "ssim": {
            "mean": f"{np.mean(ssim_vals):.6f}",
            "min": f"{np.min(ssim_vals):.6f}",
            "verdict": "IMPERCEPTIBLE" if np.mean(ssim_vals) > 0.999 else "VISIBLE",
        },
        "kl_divergence": {
            "mean": f"{np.mean(kl_vals):.8f}",
            "max": f"{np.max(kl_vals):.8f}",
            "verdict": "INDISTINGUISHABLE" if np.mean(kl_vals) < 0.001 else "DISTINGUISHABLE",
        },
        "ml_classifier": ml_results,
    }

    return results


def print_results_table(all_results: List[Dict]):
    print("\n")
    print("=" * 80)
    print("  StegX v2.0 STEGANALYSIS RESISTANCE REPORT")
    print("=" * 80)

    header = f"{'Test':<25} {'Metric':<20}"
    for r in all_results:
        header += f" {r['mode']:<18}"
    print(header)
    print("-" * len(header))

    rows = [
        ("Chi-Square", "p-value", lambda r: r["chi_square"]["mann_whitney_p"]),
        ("Chi-Square", "Verdict", lambda r: r["chi_square"]["verdict"]),
        ("RS Analysis", "p-value", lambda r: r["rs_analysis"]["mann_whitney_p"]),
        ("RS Analysis", "Verdict", lambda r: r["rs_analysis"]["verdict"]),
        ("Sample Pair", "p-value", lambda r: r["sample_pair"]["mann_whitney_p"]),
        ("Sample Pair", "Verdict", lambda r: r["sample_pair"]["verdict"]),
        ("Entropy", "Delta", lambda r: r["entropy"]["delta"]),
        ("Entropy", "Verdict", lambda r: r["entropy"]["verdict"]),
        ("PSNR", "Mean (dB)", lambda r: r["psnr"]["mean_dB"]),
        ("PSNR", "Verdict", lambda r: r["psnr"]["verdict"]),
        ("SSIM", "Mean", lambda r: r["ssim"]["mean"]),
        ("SSIM", "Verdict", lambda r: r["ssim"]["verdict"]),
        ("KL Divergence", "Mean", lambda r: r["kl_divergence"]["mean"]),
        ("KL Divergence", "Verdict", lambda r: r["kl_divergence"]["verdict"]),
        ("ML (Random Forest)", "CV Accuracy", lambda r: r["ml_classifier"].get("random_forest_cv_accuracy", "N/A")),
        ("ML (Grad. Boost)", "CV Accuracy", lambda r: r["ml_classifier"].get("gradient_boosting_cv_accuracy", "N/A")),
        ("ML Classifier", "Verdict", lambda r: r["ml_classifier"].get("verdict", "N/A")),
    ]

    for test, metric, getter in rows:
        line = f"{test:<25} {metric:<20}"
        for r in all_results:
            try:
                val = getter(r)
            except (KeyError, TypeError):
                val = "N/A"
            line += f" {str(val):<18}"
        print(line)

    print("=" * len(header))
    print()
    print("LEGEND:")
    print("  Chi-Square/RS/SPA p-value > 0.05 = UNDETECTED (no statistical anomaly)")
    print("  Entropy Delta < 0.01 = UNDETECTED")
    print("  PSNR > 50 dB = IMPERCEPTIBLE")
    print("  SSIM > 0.999 = IMPERCEPTIBLE")
    print("  KL Divergence < 0.001 = INDISTINGUISHABLE")
    print("  ML Accuracy ~50% = random guessing = UNDETECTED")
    print()


def main():
    parser = argparse.ArgumentParser(description="StegX Steganalysis Resistance Suite")
    parser.add_argument("--num-images", type=int, default=30, help="Number of test images (default: 30)")
    parser.add_argument("--modes", nargs="+", default=["standard", "adaptive", "matrix", "adaptive_matrix"],
                        help="StegX modes to test")
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  StegX v2.0 Steganalysis Resistance Test Suite")
    print("=" * 60)
    print(f"  Images: {args.num_images}")
    print(f"  Modes:  {', '.join(args.modes)}")
    print()

    print("[1/3] Generating cover images...")
    cover_paths = generate_test_images(n=args.num_images)
    print(f"  Generated {len(cover_paths)} cover images")

    all_results = []
    for mode in args.modes:
        print(f"\n[2/3] Generating stego images (mode: {mode})...")
        stego_paths = generate_stego_images(cover_paths, mode)
        print(f"  Generated {len(stego_paths)} stego images")

        if len(stego_paths) < 5:
            print(f"  SKIPPING {mode}: not enough stego images generated")
            continue

        results = run_full_analysis(cover_paths, stego_paths, mode)
        all_results.append(results)

    print("\n[3/3] Generating report...")
    if all_results:
        print_results_table(all_results)

        report_path = RESULTS_DIR / "steganalysis_report.json"
        with open(report_path, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"  Full report saved to: {report_path}")
    else:
        print("  ERROR: No results generated. Check if StegX is installed correctly.")
        print("  Try: pip install -e . && python -m stegx --version")


if __name__ == "__main__":
    main()
