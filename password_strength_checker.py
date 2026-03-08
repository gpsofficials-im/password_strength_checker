"""
Password Strength Checker
=========================
A beginner-friendly cybersecurity project that analyzes password strength.
This program checks various security conditions and provides feedback.

Author: Python Developer
Purpose: Cyber Security Education Project
"""

import re  # Regular expressions for pattern matching


def check_length(password):
    """
    Check if password meets minimum length requirement.
    
    Args:
        password (str): The password to check
        
    Returns:
        bool: True if length >= 8, False otherwise
    """
    return len(password) >= 8


def check_uppercase(password):
    """
    Check if password contains at least one uppercase letter.
    
    Args:
        password (str): The password to check
        
    Returns:
        bool: True if uppercase letter exists, False otherwise
    """
    # Regex: look for at least one uppercase letter (A-Z)
    return bool(re.search(r'[A-Z]', password))


def check_lowercase(password):
    """
    Check if password contains at least one lowercase letter.
    
    Args:
        password (str): The password to check
        
    Returns:
        bool: True if lowercase letter exists, False otherwise
    """
    # Regex: look for at least one lowercase letter (a-z)
    return bool(re.search(r'[a-z]', password))


def check_numbers(password):
    """
    Check if password contains at least one number.
    
    Args:
        password (str): The password to check
        
    Returns:
        bool: True if number exists, False otherwise
    """
    # Regex: look for at least one digit (0-9)
    return bool(re.search(r'[0-9]', password))


def check_special_characters(password):
    """
    Check if password contains at least one special character.
    
    Args:
        password (str): The password to check
        
    Returns:
        bool: True if special character exists, False otherwise
    """
    # Regex: look for at least one special character (!@#$%^&* etc.)
    return bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",.<>?/\\`]', password))


def check_common_passwords(password):
    """
    Check if password exists in a list of common weak passwords.
    This simulates a dictionary attack.
    
    Args:
        password (str): The password to check
        
    Returns:
        bool: True if password is common/weak, False if unique/strong
    """
    # List of common weak passwords (top 50 most used passwords)
    common_passwords = [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "iloveyou", "trustno1", "sunshine",
        "master", "welcome", "shadow", "ashley", "football",
        "jesus", "michael", "ninja", "mustang", "password1",
        "password123", "admin", "letmein", "monkey", "access",
        "hello", "charlie", "donald", "princess", "qwerty123",
        "admin123", "root", "toor", "pass", "test",
        "guest", "master123", "changeme", "orange", "secret",
        "123qwe", "zxcvbn", "1234567890", "password12", "login"
    ]
    
    return password.lower() in common_passwords


def analyze_password(password):
    """
    Analyze the password and return a detailed report.
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Dictionary containing analysis results
    """
    # Check each security condition
    results = {
        "length": check_length(password),
        "uppercase": check_uppercase(password),
        "lowercase": check_lowercase(password),
        "numbers": check_numbers(password),
        "special": check_special_characters(password),
        "common": check_common_passwords(password)
    }
    
    return results


def calculate_strength_score(results):
    """
    Calculate the overall strength score based on check results.
    
    Args:
        results (dict): Dictionary containing analysis results
        
    Returns:
        tuple: (strength_level, score) where level is a string and score is 0-6
    """
    # Start with base score
    score = 0
    
    # Add points for each condition met
    if results["length"]:
        score += 1
    if results["uppercase"]:
        score += 1
    if results["lowercase"]:
        score += 1
    if results["numbers"]:
        score += 1
    if results["special"]:
        score += 1
    
    # Being in common passwords list severely weakens the password
    if results["common"]:
        score = 0  # Reset score if password is common
    
    # Determine strength level based on score
    if results["common"]:
        strength = "Very Weak"
    elif score <= 2:
        strength = "Very Weak"
    elif score == 3:
        strength = "Weak"
    elif score == 4:
        strength = "Medium"
    elif score >= 5:
        strength = "Strong"
    else:
        strength = "Unknown"
    
    return strength, score


def display_analysis_report(password, results, strength, score):
    """
    Display a clear analysis report showing which conditions passed or failed.
    
    Args:
        password (str): The analyzed password
        results (dict): Analysis results
        strength (str): Strength classification
        score (int): Strength score (0-6)
    """
    print("\n" + "=" * 60)
    print("              PASSWORD STRENGTH ANALYSIS REPORT")
    print("=" * 60)
    
    # Display password (masked for security)
    masked_password = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "*" * len(password)
    print(f"\nPassword Analyzed: {masked_password}")
    
    # Display analysis results
    print("\n--- Security Conditions Check ---")
    print(f"  [P] Minimum 8 characters:     {'PASS' if results['length'] else 'FAIL'}")
    print(f"  [P] Uppercase letters:      {'PASS' if results['uppercase'] else 'FAIL'}")
    print(f"  [P] Lowercase letters:      {'PASS' if results['lowercase'] else 'FAIL'}")
    print(f"  [P] Numbers:                {'PASS' if results['numbers'] else 'FAIL'}")
    print(f"  [P] Special characters:     {'PASS' if results['special'] else 'FAIL'}")
    print(f"  [P] Not a common password:  {'PASS' if not results['common'] else 'FAIL'}")
    
    # Display strength classification
    print("\n--- Strength Classification ---")
    
    # Color coding (using text-based indicators)
    if strength == "Very Weak":
        indicator = "[RED]"
    elif strength == "Weak":
        indicator = "[ORANGE]"
    elif strength == "Medium":
        indicator = "[YELLOW]"
    elif strength == "Strong":
        indicator = "[GREEN]"
    else:
        indicator = "[WHITE]"
    
    print(f"  {indicator} Strength Level: {strength}")
    print(f"  Score: {score}/6 conditions met")
    
    print("\n" + "=" * 60)


def display_suggestions(results, strength):
    """
    Display suggestions to create a stronger password if needed.
    
    Args:
        results (dict): Analysis results
        strength (str): Current strength classification
    """
    if strength in ["Strong", "Medium"]:
        print("\n[*] Great job! Your password is reasonably strong.")
        print("   Consider using a password manager for added security.")
        return
    
    print("\n[SUGGESTIONS] Suggestions to improve your password:")
    print("-" * 40)
    
    suggestions = []
    
    if not results["length"]:
        suggestions.append("* Use at least 8 characters (longer is better)")
    if not results["uppercase"]:
        suggestions.append("* Add uppercase letters (A-Z)")
    if not results["lowercase"]:
        suggestions.append("* Add lowercase letters (a-z)")
    if not results["numbers"]:
        suggestions.append("* Include numbers (0-9)")
    if not results["special"]:
        suggestions.append("* Add special characters (!@#$%^&*...)")
    if results["common"]:
        suggestions.append("* AVOID common passwords - they're easily cracked!")
        suggestions.append("* Never use: password, 123456, qwerty, etc.")
    
    for suggestion in suggestions:
        print(suggestion)
    
    print("\n[TIPS] Password Tips:")
    print("   * Use a passphrase: 'Correct-Horse-Battery-Staple'")
    print("   * Mix random words with numbers and symbols")
    print("   * Consider using a password manager")
    print("   * Use different passwords for different accounts")


def get_user_password():
    """
    Get password input from user with proper security.
    
    Returns:
        str: The password entered by user
    """
    print("\n" + "=" * 60)
    print("           PASSWORD STRENGTH CHECKER")
    print("  A Beginner Cybersecurity Project")
    print("=" * 60)
    
    print("\nThis program analyzes password strength by checking:")
    print("  [x] Minimum length (8+ characters)")
    print("  [x] Uppercase letters")
    print("  [x] Lowercase letters")
    print("  [x] Numbers")
    print("  [x] Special characters")
    print("  [x] Common password list (dictionary attack check)")
    
    # Get password input
    password = input("\nEnter a password to analyze: ")
    
    # Remove any whitespace/newline characters from the password
    password = password.strip()
    
    return password


def main():
    """
    Main function to run the Password Strength Checker program.
    """
    # Get password from user
    password = get_user_password()
    
    if not password:
        print("\n[!] No password entered. Exiting.")
        return
    
    # Analyze the password
    results = analyze_password(password)
    
    # Calculate strength score and classification
    strength, score = calculate_strength_score(results)
    
    # Display the analysis report
    display_analysis_report(password, results, strength, score)
    
    # Display suggestions if password is weak
    display_suggestions(results, strength)
    
    print("\n" + "=" * 60)
    print("  Thank you for using Password Strength Checker!")
    print("=" * 60 + "\n")


# Run the program
if __name__ == "__main__":
    main()
