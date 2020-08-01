from flask import Flask

SECRET = 'b58f32c21153d898849d26af4c3068bc'

app = Flask(__name__)


@app.route("/")
def hello():
    test('b58f32c21153d898849d26af4c3068bc')
    test(123, 'abc', 'b58f32c21153d898849d26af4c3068bc')
    return f'Hello World! Service is UP!! \n Secret: {SECRET}'

def test(a, *r):
    return 'b58f32c21153d898849d26af4c3068bc'

if __name__ == '__main__':
    app.run(port=1111)
