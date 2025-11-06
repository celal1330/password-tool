# Password Validator & Generator

 A straightforward yet effective CLI tool for creating strong passwords, evaluating their strength, and comprehending password entropy.


 ## Features

 Generating memorable passphrases and secure random passwords
 SHA-256 hashing, entropy computation, and password strength analysis
 Typical password checks
 Password criteria that can be customized

 ## Application

 ```bash password_tool.py in Python ```

 ### Specifics

 #### 1. Random password generation; length customization; character type selection; and the ability to omit ambiguous characters

 #### 2. Passphrase Creation: Remarkable word combinations and a customizable separator

 #### 3. Password validation: thorough strength analysis, comments and recommendations, and standard password checks

 #### 4. Entropy Calculation - Entropy in bits - Rough crack time estimates

 #### 5. Hashing: For safe storage, use SHA-256 hashing

 ## Requirements for Password Strength

 **Length**: at least 8 characters, but 16+ are advised; **Diversity**: capital, lowercase, digits, and special characters; **Entropy**: 60+ bits are advised; **Avoid**: Sequential characters and common passwords

## Safety

 Creates unpredictable passwords by utilizing the `secrets` module for cryptographic randomness.
 Verifies against a database of popular passwords

 ## Illustration

 ```python import PasswordGenerator, PasswordValidator from password_tool

 # Create a password using gen = PasswordGenerator().
 password = gen.generate(exclude_ambiguous=True, length=16)

 # Verify the password val = PasswordValidator() result = val.validate(password) print(f"Strength: {result['strength']}")
 ```

 ## Technical Specifications

 **Language**: Python 3.x - **Libraries**: hashlib, re, random, string, and secrets
 **Hashing**: SHA-256 - **Randomness**: Secure cryptography

 ## Developer

Celal AYDIN
