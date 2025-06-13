# 🛠️ StegX Development Roadmap – v1.2.0 (Planned)

This document outlines the upcoming features and improvements planned for StegX version 1.2.0. These changes are designed to enhance functionality, performance, and security while extending compatibility and usability across different use cases.

---

## 📅 Release Target

- **Version**: `v1.2.0`
- **Planned Release**: Q4 2025 (Target: December 12, 2025)
- **Milestone**: [GitHub Milestone Link](https://github.com/Delta-Sec/StegX/milestone/)

---

## 🚀 Upcoming Features

### 1. [Feature] JPEG (DCT-based) Steganography Support
- Implement DCT coefficient manipulation for baseline JPEG images.
- Maintain AES-256-GCM encryption and data integrity.
- Detect cover image support automatically.
- Target: Broaden file format compatibility.

➡️ [Issue #1](https://github.com/Delta-Sec/StegX/issues/1)

---

### 2. [UX] Colorful and Interactive CLI Output Using Rich
- Use `rich` for modern CLI design.
- Add themes, progress bars, and structured logs.
- Toggle via `--verbose` and `--quiet` CLI flags.
- Optional dependency fallback.

➡️ [Issue #2](https://github.com/Delta-Sec/StegX/issues/2)

---

### 3. [Feature] Entropy-Aware Capacity Estimator
- Analyze image entropy pre-encoding to suggest capacity limits.
- Provide CLI simulation via `--analyze`.
- Warn users on low-entropy image choices.

➡️ [Issue #3](https://github.com/Delta-Sec/StegX/issues/3)

---

### 4. [Security] Fuzz Testing Integration
- Integrate Hypothesis for property-based testing.
- Simulate malformed inputs (files, metadata, arguments).
- Ensure crash-resistance and input validation.
- Extend pytest framework.

➡️ [Issue #4](https://github.com/Delta-Sec/StegX/issues/4)

---

## 🧪 Security & QA Goals

- All new features covered by test cases.
- Lintian/Codestyle compliant packaging.
- 100% compatibility with Debian `.deb` pipeline.
- Maintain zero-crash policy via pre-release fuzz tests.

---

## 📌 Notes

- All features are in active development under `dev` branch.
- Community feedback welcomed via GitHub Issues or Discussions.

---

## 📜 License

This roadmap is part of the open-source MIT-licensed StegX project.
