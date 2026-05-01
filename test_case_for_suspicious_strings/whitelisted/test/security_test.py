# Security test cases
def test_shell_injection():
    # Test if system() is vulnerable
    result = system("echo test")
    assert result == 0
    
def test_exec():
    # Test exec() protection
    exec("print('safe')")
