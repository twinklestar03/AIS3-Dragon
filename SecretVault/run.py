from secret_vault import SecretVault

if __name__ == '__main__':
    sv = SecretVault(3333, 'sqlite:///database.db')
    sv.run()