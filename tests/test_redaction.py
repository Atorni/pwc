from pwc.redaction import redact, redact_dict


def test_redacts_anthropic_key():
    r = redact("token sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV12345 here")
    assert "sk-ant-" not in r.text
    assert "<REDACTED:ANTHROPIC_KEY>" in r.text
    assert r.count == 1


def test_redacts_private_key_block():
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\nxyz\n-----END OPENSSH PRIVATE KEY-----"
    r = redact(text)
    assert "PRIVATE KEY" not in r.text.replace("REDACTED:PRIVATE_KEY", "")
    assert r.count == 1


def test_redacts_password_assignment():
    r = redact("mysql -u root password=Sup3rSecret!")
    assert "Sup3rSecret" not in r.text
    assert "password=<REDACTED:ASSIGNED_SECRET>" in r.text


def test_redacts_inline_password_flag():
    r = redact("mysql -uroot -pMyPassw0rd dbname")
    assert "MyPassw0rd" not in r.text
    assert "<REDACTED:PASSWORD>" in r.text


def test_redacts_basic_auth_url():
    r = redact("curl https://admin:hunter2@example.com/")
    assert "hunter2" not in r.text


def test_redact_dict_counts():
    data = {"a": "sk-ant-aaaaaaaaaaaaaaaaaaaaaa", "b": ["password=zzzz"], "c": 5}
    cleaned, count = redact_dict(data)
    assert count == 2
    assert cleaned["c"] == 5


def test_no_false_positive_on_plain_text():
    r = redact("nmap -sV 10.10.10.10")
    assert r.count == 0
    assert r.text == "nmap -sV 10.10.10.10"
