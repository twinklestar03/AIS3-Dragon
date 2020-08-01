import requests


class SecretVault:
    AUTH = '/auth'
    GET_SECRET = '/get_secret/{}'
    IS_EXPOSE = '/is_expose/{}'
    def __init__(self, server, api_key_file):
        self.server = server
        with open(api_key_file, 'r') as f:
            self.api_key = f.readline() 
        res = requests.get(self.get_url(self.server, self.AUTH), headers={'api_key': self.api_key})

        # Exchange temporary token with server
        if 'success' in res.text:
            self.token = res.json()['token']

        else:
            raise Exception('Auth Error')
    
    @staticmethod
    def get_url(server, endpoint):
        return 'http://' + server + '/' + endpoint

    def check_is_expose(self, h):
        req = self.IS_EXPOSE.format(h)
        res = requests.get(self.get_url(self.server, req), headers={'access_token': self.token})

        data = res.json()

        if data['status'] == 'success':
            return False
        else:
            return True

    def get_secret(self, secret_name):
        req = self.GET_SECRET.format(secret_name)

        res = requests.get(self.get_url(self.server, req), headers={'access_token': self.token})

        data = res.json()

        if data['status'] == 'success':
            return data['result']
        else:
            return None