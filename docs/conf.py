# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join("..")))

import securesystemslib

# -- Project information -----------------------------------------------------

project = "securesystemslib"
copyright = "2023, New York University and the securesystemslib contributors"
author = "New York University and the securesystemslib contributors"


# -- General configuration ---------------------------------------------------

master_doc = "index"

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.napoleon",
    "sphinx.ext.autosummary",
    "sphinx.ext.autosectionlabel",
]

autosectionlabel_prefix_document = True


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = "sphinx_rtd_theme"

# -- Autodoc configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html

# Shorten paths
add_module_names = False
python_use_unqualified_type_names = True

# Show typehints in argument doc lines, but not in signatures
autodoc_typehints = "description"

autodoc_default_options = {
    "members": True,
    "inherited-members": "Exception",  # excl. members inherited from 'Exception'
}

# Version
version = securesystemslib.__version__
