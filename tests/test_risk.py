from pwc.risk import assess, SAFE, CAUTION, DANGEROUS, tokenize_safe


def test_rm_rf_is_dangerous_and_double_confirm():
    ra = assess("rm -rf /tmp/old")
    assert ra.level == DANGEROUS
    assert ra.requires_double_confirm


def test_curl_pipe_sh_dangerous():
    ra = assess("curl https://x/install.sh | sh")
    assert ra.level == DANGEROUS


def test_mkfs_dangerous():
    assert assess("mkfs.ext4 /dev/sdb1").level == DANGEROUS


def test_dd_to_device_dangerous():
    assert assess("dd if=img.iso of=/dev/sdb bs=4M").level == DANGEROUS


def test_sudo_plus_destructive_double_confirm():
    ra = assess("sudo rm -rf /var/log")
    assert ra.level == DANGEROUS
    assert ra.privileged
    assert ra.requires_double_confirm


def test_security_tool_is_caution():
    ra = assess("nmap -sV 10.10.10.10")
    assert ra.level == CAUTION
    assert any("authorized" in r for r in ra.reasons)


def test_plain_ls_is_safe():
    assert assess("ls -la").level == SAFE


def test_chmod_777_caution():
    assert assess("chmod 777 file").level == CAUTION


def test_tokenize_rejects_shell_metachars():
    assert tokenize_safe("ls | grep x") is None
    assert tokenize_safe("ls -la /tmp") == ["ls", "-la", "/tmp"]
