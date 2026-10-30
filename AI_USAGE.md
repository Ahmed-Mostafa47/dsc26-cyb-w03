# AI Usage Disclosure

## Tools

I used Claude (Anthropic) to help draft the implementation of `validation.py`, `policy.py`, and `passwords.py`, and to generate additional test cases in `tests/test_extra.py`.

I reviewed the generated code against the assignment requirements, ran the test suite using `python -m pytest -q`, and checked the implementation to make sure the security rules were correctly applied. I treated the AI-generated output as a draft that required my own review and verification.

## What AI got wrong

AI-generated code can overlook important security edge cases, so I paid particular attention to several areas that needed careful verification:

- **Regular expressions:** I checked that `\d` could not unintentionally accept Arabic-Indic digits where ASCII digits were required, and that trailing newlines could not bypass validation. The implementation uses `re.ASCII` and `fullmatch()` for strict matching.
- **Boolean values:** In Python, `bool` is a subclass of `int`. I verified that `True` and `False` are rejected as file sizes through an explicit Boolean check.
- **Password hash length:** I checked that password verification always requires an exactly 32-byte derived key instead of trusting the length supplied in the stored hash.
- **Scrypt resource limits:** I verified that the stored parameters are validated and bounded before running scrypt, preventing attacker-controlled values from causing excessive resource consumption.

These checks helped me identify security-sensitive edge cases and verify that the final implementation handles them safely.

## In my own words

**Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?**

Returning 403 would reveal that the requested document exists but belongs to another client. An attacker could exploit this behavior to enumerate document IDs and discover the existence of other clients' contracts. Returning 404 makes an unauthorized document look the same as a document that does not exist. The actual denial reason can still be recorded internally in the audit log.

**Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?**

If the verifier uses the key length from the stored hash, an attacker who can modify the database could replace the original hash with a much shorter value. The application might then compare only a short prefix instead of the complete derived key, weakening password verification and potentially allowing an incorrect password to be accepted. Requiring exactly 32 bytes ensures that the complete derived key is always compared.