from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


import stegx

project = "StegX"
author = "Delta-Sec"
copyright = "2025-2026, Delta-Sec"
release = stegx.__version__
version = ".".join(release.split(".")[:2])


extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "sphinx_autodoc_typehints",
    "sphinx_copybutton",
    "sphinx_design",
]


myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "linkify",
    "replacements",
    "smartquotes",
    "strikethrough",
    "substitution",
    "tasklist",
]
myst_heading_anchors = 3
myst_substitutions = {
    "release": release,
    "version": version,
}

source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
language = "en"
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


html_theme = "furo"
html_title = f"StegX {release}"
html_static_path = ["_static"]
html_theme_options = {
    "source_repository": "https://github.com/Delta-Sec/StegX/",
    "source_branch": "main",
    "source_directory": "docs/source/",
    "navigation_with_keys": True,
    "sidebar_hide_name": False,
    "top_of_page_button": "edit",
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/Delta-Sec/StegX",
            "html": "",
            "class": "fa-brands fa-solid fa-github fa-2x",
        },
    ],
    "light_css_variables": {
        "color-brand-primary": "#1f6feb",
        "color-brand-content": "#1f6feb",
    },
    "dark_css_variables": {
        "color-brand-primary": "#58a6ff",
        "color-brand-content": "#58a6ff",
    },
}


templates_path = ["_templates"]

autosummary_generate = True
autodoc_typehints = "description"
autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
    "member-order": "bysource",
}
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False


intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "cryptography": ("https://cryptography.io/en/latest/", None),
    "pillow": ("https://pillow.readthedocs.io/en/stable/", None),
}


nitpicky = False
suppress_warnings = ["myst.xref_missing"]
