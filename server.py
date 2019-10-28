from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO

app = Flask(__name__, static_url_path='', static_folder='www/')
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# https://flask-socketio.readthedocs.io/en/latest/

@socketio.on('register')
def handle_message(message):
    print('[*] register client: ' + message)

@socketio.on('message')
def handle_message(message):
    print('[*] client message: ' + message)

@app.route('/')
def root():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    socketio.run(app)
