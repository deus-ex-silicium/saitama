import frida, sys


class DeviceManager:
    def __init__(self):
        pass
    
    def get_devices(self):
        return frida.get_device_manager().enumerate_devices()
    
    def get_processes(self, device):
        return sorted(device.enumerate_processes(), key=lambda d: d.name.lower())
    
    def get_installed_applications(self, device):
        return sorted(device.enumerate_applications(), key=lambda d: d.identifier.lower())

    def attach(self, device, process_name, script_location):
        with open(script_location, "r") as f:
            script_code = f.read()
        session = device.attach(process_name)
        script = session.create_script(script_code)
        def on_message(message, data):
            print(message)
            print(data)
        script.on('message', on_message)
        script.load()

    # can be faster/earlier spawned?
    def spawn(self, device, process_name, script_location):
        with open(script_location, "r") as f:
            script_code = f.read()
        pid = device.spawn([process_name])
        session = device.attach(pid)
        script = session.create_script(script_code)
        def on_message(message, data):
            print(message)
            print(data)
        script.on('message', on_message)
        script.load()
        device.resume(pid)