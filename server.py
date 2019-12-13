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

# https://flask-socketio.readthedocs.io/en/latest/

@socketio.on('register')
def handle_message(message):
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
def handle_message(message):
    logging.debug('[*] device attached')

@app.route('/api/v1/devices')
def api_devices():
    logging.debug('[*] Endpoint /api/v1/devices reached')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    devices_dicts = [{"id": d.id, "name": d.name, "type": d.type} for d in devices]
    logging.debug('[*] Devices: %s' % devices_dicts)
    return jsonify(devices_dicts)

@app.route('/api/v1/device/details')
def api_device_details():
    logging.debug('[*] Endpoint /api/v1/device/details reached')
    device_id = request.args.get('device_id')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    device_dict = [{"id": d.id, "name": d.name, "type": d.type} for d in devices if d.id == device_id][0]
    logging.debug('[*] Device: %s' % device_dict)
    return jsonify(device_dict)

@app.route('/api/v1/device/applications')
def api_device_applications():
    logging.debug('[*] Endpoint /api/v1/device/applications reached')
    device_id = request.args.get('device_id')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    device = list(filter(lambda d: d.id == device_id, devices))[0]
    applications = device_manager.get_installed_applications(device)
    logging.debug('[*] Applications: %s' % applications)
    applications_dicts = [{"identifier": a.identifier, "name": a.name} for a in applications]
    return jsonify(applications_dicts)

@app.route('/api/v1/device/processes')
def api_device_processes():
    logging.debug('[*] Endpoint /api/v1/device/processes reached')
    device_id = request.args.get('device_id')
    device_manager = DeviceManager()
    devices = device_manager.get_devices()
    device = list(filter(lambda d: d.id == device_id, devices))[0]
    processes = device_manager.get_processes(device)
    logging.debug('[*] Processes: %s' % processes)
    processes_dicts = [{"pid": p.pid, "name": p.name} for p in processes]
    return jsonify(processes_dicts)

@app.route('/')
def root():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    socketio.run(app)