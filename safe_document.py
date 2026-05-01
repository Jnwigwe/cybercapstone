# Safe Python Script - InfectionPoint Test File
# This is a perfectly normal Python program

def greet(name):
    """Greet a user by name."""
    print(f"Hello, {name}! Welcome to InfectionPoint demo.")

def add_numbers(a, b):
    """Add two numbers and return the result."""
    return a + b

def fibonacci(n):
    """Generate Fibonacci sequence up to n."""
    sequence = []
    a, b = 0, 1
    while a < n:
        sequence.append(a)
        a, b = b, a + b
    return sequence

if __name__ == "__main__":
    greet("Appar")
    result = add_numbers(10, 20)
    print(f"10 + 20 = {result}")
    fib = fibonacci(100)
    print(f"Fibonacci: {fib}")
    print("This file is completely safe!")
