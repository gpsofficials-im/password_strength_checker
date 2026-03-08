"""
Test script to demonstrate Password Strength Checker functionality
This script runs the checker with various test passwords to show all features
"""

import password_strength_checker as psc

# Test passwords to demonstrate all strength levels
test_passwords = [
    "123456",           # Very Weak - common password
    "password",         # Very Weak - common password
    "abc",              # Very Weak - too short
    "abcd1234",         # Weak - no uppercase, no special
    "Abcd1234",         # Medium - missing special char
    "Abcd1234!",        # Strong - meets all criteria
    "MyStr0ng!Pass#2024",  # Very Strong
]

print("=" * 70)
print("        PASSWORD STRENGTH CHECKER - TEST DEMONSTRATION")
print("=" * 70)

for password in test_passwords:
    # Analyze the password
    results = psc.analyze_password(password)
    
    # Calculate strength
    strength, score = psc.calculate_strength_score(results)
    
    # Display results
    psc.display_analysis_report(password, results, strength, score)
    psc.display_suggestions(results, strength)
    
    print("\n" + "-" * 70)

print("\n" + "=" * 70)
print("                    TEST COMPLETE")
print("=" * 70)
