import logging
import json
from flask import Flask, render_template, send_from_directory, request
from flask_socketio import SocketIO
from flask import jsonify
from flask_cors import CORS

from lib.core.device_manager import DeviceManager

# refactor below + disable CORS in future when prod ready
app = Flask(__name__, static_url_path='', static_folder='web_app/')
app.config['SECRET_KEY'] = 'secret!'
CORS(app)
socketio = SocketIO(app)

# https://flask.palletsprojects.com/en/1.1.x/patterns/apierrors/
class APIException(Exception):
    def __init__(self, message, status_code=500, payload=None):
        Exception.__init__(self)
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

# https://flask-socketio.readthedocs.io/en/latest/
@socketio.on('register')
def handle_register(message):
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    processes = device_manager.get_processes(devices[2])
    # example usage below
    # device_manager.attach(devices[2], "com.citynav.jakdojade.pl.android", "modules/core/hello.js")
    logging.debug('[*] register client: ' + message)

@socketio.on('message')
def handle_message(message):
    logging.debug('[*] client message: ' + message)

@socketio.on('device_attach')
def handle_attach(message):
    logging.debug('[*] device attached')

@app.route('/api/v1/devices')
def api_devices():
    logging.debug('[*] /api/v1/devices')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    devices_dicts = [{"id": d.id, "name": d.name, "type": d.type} for d in devices]
    logging.debug(f'[*] {json.dumps(devices_dicts, indent=4, sort_keys=True)}')
    return jsonify(devices_dicts)

@app.route('/api/v1/device/details')
def api_device_details():
    device_id = request.args.get('device_id')
    logging.debug(f'[*] /api/v1/device/details?device_id={device_id}')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    device_dict = [{"id": d.id, "name": d.name, "type": d.type} for d in devices if d.id == device_id][0]
    logging.debug(f'[*] {json.dumps(device_dict, indent=4, sort_keys=True)}')
    return jsonify(device_dict)

@app.route('/api/v1/device/applications')
def api_device_applications():
    device_id = request.args.get('device_id')
    logging.debug(f'[*] /api/v1/device/applications?device_id={device_id}')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    device = list(filter(lambda d: d.id == device_id, devices))[0]
    try:
        applications = device_manager.get_installed_applications(device)
    except Exception as e:
        raise APIException(str(e), status_code=501)
    else:
        applications_dicts = [{"identifier": a.identifier, "name": a.name} for a in applications]
        logging.debug(f'[*] {json.dumps(applications_dicts, indent=4, sort_keys=True)}')
        return jsonify(applications_dicts)

@app.route('/api/v1/device/processes')
def api_device_processes():
    device_id = request.args.get('device_id')
    logging.debug(f'[*] /api/v1/device/processes?device_id={device_id}')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    device = list(filter(lambda d: d.id == device_id, devices))[0]
    try:
        processes = device_manager.get_processes(device)
    except Exception as e:
        raise APIException(str(e), status_code=501)
    else:
        processes_dicts = [{"pid": p.pid, "name": p.name} for p in processes]
        logging.debug(f'[*] {json.dumps(processes_dicts, indent=4, sort_keys=True)}')
        return jsonify(processes_dicts)

@app.errorhandler(APIException)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

@app.route('/')
def root():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    port = 5000
    logging.info(f'[*] Started flask server on {port}')
    socketio.run(app, port=port)