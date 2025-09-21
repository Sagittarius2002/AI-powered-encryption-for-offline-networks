def decrypt_reverse(token: str) -> str:
    if not isinstance(token, str):
        token = str(token)
    return token[::-1]