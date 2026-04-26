class Stegx < Formula
  include Language::Python::Virtualenv

  desc "Authenticated LSB steganography with Argon2id, AES-GCM/ChaCha20-Poly1305"
  homepage "https://github.com/Delta-Sec/StegX"
  url "https://files.pythonhosted.org/packages/source/s/stegx-cli/stegx_cli-2.0.0.tar.gz"
  sha256 "REPLACE_WITH_SDIST_SHA256_AFTER_PYPI_RELEASE"
  license "MIT"
  head "https://github.com/Delta-Sec/StegX.git", branch: "main"

  depends_on "rust" => :build
  depends_on "python@3.12"

  resource "argon2-cffi" do
    url "https://files.pythonhosted.org/packages/source/a/argon2-cffi/argon2_cffi-23.1.0.tar.gz"
    sha256 "REPLACE_WITH_ARGON2_SHA256"
  end

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-44.0.1.tar.gz"
    sha256 "REPLACE_WITH_CRYPTOGRAPHY_SHA256"
  end

  resource "Pillow" do
    url "https://files.pythonhosted.org/packages/source/p/Pillow/pillow-10.4.0.tar.gz"
    sha256 "REPLACE_WITH_PILLOW_SHA256"
  end

  resource "tqdm" do
    url "https://files.pythonhosted.org/packages/source/t/tqdm/tqdm-4.66.5.tar.gz"
    sha256 "REPLACE_WITH_TQDM_SHA256"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/stegx --version")
  end
end
