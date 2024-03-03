import string
import random

print('''
        _______            
      /\       \           
     /()\   ()  \          
    /    \_______\         
    \    /()     /         
     \()/   ()  /          
      \/_____()/
      
    Password Generator                                                                                                                                     
    ''')
def generate_password():
    length = 12
    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation

    password_chars = [
        random.choice(uppercase_letters),
        random.choice(lowercase_letters),
        random.choice(digits),
        random.choice(symbols)
    ]

    remaining_length = length - 4  # Subtracting 4 because we already have 4 characters
    all_chars = uppercase_letters + lowercase_letters + digits + symbols
    password_chars.extend(random.choices(all_chars, k=remaining_length))
    random.shuffle(password_chars)
    return ''.join(password_chars)

password = generate_password()
print("Generated Password:", password)
