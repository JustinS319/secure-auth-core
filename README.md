# Secure Authentication Core

A small, single-file user authentication system written in pure Python with no external dependencies.

Professor asked for a "mini-program". I went a bit beyond a simple calculator.

# Features
- Password hashing: PBKDF2-HMAC-SHA256 (300 000 iterations) with per-user salts
- Real 2FA via Gmail SMTP (tested with email + SMS)
- Account lockout after 5 failed attempts (15-minute timeout)
- Complete audit log (`auth_audit.log`)
- Role-based access: regular user → admin → master (with irreversible master transfer)
- Graceful shutdown, config-driven paths, modern type hints
- Runs on any fresh Python 3.10+ install — no venv or pip required

# Why I made it this way
- Zero third-party libraries - works on restricted/lab machines
- PBKDF2 instead of Argon2 - standard library only (still far stronger than most production code)
- Dashboard kept minimal on purpose — authentication should be a reusable service
- Uses JSON because I haven’t taught myself SQL yet

# Author
Justin Somerville   
This is my first program I truly like.

Feel free to use, fork, or study.  
Apache-2.0 licensed.

— Justin