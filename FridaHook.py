import sys
import frida

# Full file name: hook_[platform]_[name].js
js_modules = [
    {'platform': 'ios', 'name': 'byte'},
]

# For frida version 15 or higher
# Please use real App name for `name` and package name for `identifier` on Android
# For Android native processes or iOS processes, keep identifier and name as same
processes_to_hook = [
    # {'identifier': 'com.ss.android.ugc.aweme', 'name': '抖音'}, # Android
    # {'identifier': 'com.ss.android.ugc.aweme.lite', 'name': '抖音极速版'}, # Android
    # {'identifier': 'com.ss.iphone.ugc.Aweme', 'name': '抖音'}, # iOS
    {'identifier': 'com.ss.iphone.ugc.Aweme', 'name': '抖音内测'}, # iOS
]

class Log:
    @staticmethod
    def send(msg):
        print('[Send] ' + msg)

    @staticmethod
    def println(msg):
        print(msg)

    @staticmethod
    def info(msg):
        print('[Info] ' + msg)

    @staticmethod
    def warn(msg):
        print('\033[0;33m[Warning] ' + msg + '\033[0m')

    @staticmethod
    def error(msg):
        print('\033[0;31m[Error] ' + msg + '\033[0m')


def on_message(message, data):
    if message['type'] == 'send':
        Log.send(message['payload'])
    elif message['type'] == 'error':
        Log.error(message['description'])
    else:
        Log.error(message)


def init_device():
    Log.info('Current frida version: '+str(frida.__version__))
    manager = frida.get_device_manager()
    Log.println('Select a frida device:')
    devices = manager.enumerate_devices()
    i = 0
    for ldevice in devices:
        i = i + 1
        Log.println(str(i) + ' => ' + str(ldevice))
    if i == 4:
        select = 4
        Log.warn('Auto select the only usb device...')
    elif i == 1 or i == 2:
        select = 1
        Log.warn('Auto select local system device...')
    else:
        select = int(input())
    if select > len(devices):
        Log.error('Out of range.')
        sys.exit(1)
    device_id = devices[select - 1].id
    
    device = manager.get_device(device_id, 1)
    Log.info('Connect to device \''+device.name+'\' successfully.')
    return device
    

if __name__ == '__main__':
    try:
        device = init_device()
        all_processes = device.enumerate_processes()
        for per_hook_process in processes_to_hook:
            try:
                device.get_process(per_hook_process['name'])
            except frida.ProcessNotFoundError as e:
                Log.warn('Unable to find process \''+per_hook_process['name']+'\', try to spawn...')
                # Must use identifier to spawn
                try:
                    pid = device.spawn(per_hook_process['identifier'])
                    device.resume(pid)
                except frida.ExecutableNotFoundError as e2:
                    Log.error('Unable to find execuable \''+per_hook_process['name']+'\'.')
            
            session = device.attach(per_hook_process['name'])
            
            for js_module in js_modules:
                full_script_name = 'hook_' + js_module['platform'] + '_' + js_module['name'] + '.js'
                name_var = 'var __name = "'+per_hook_process['name']+'";'
                identifier_var = 'var __identifier = "'+per_hook_process['identifier']+'";'
                
                with open(full_script_name, 'rb') as f:
                    Log.info('Inject script name: ' + full_script_name)
                    script = session.create_script(name_var + identifier_var + f.read().decode('utf8'))
                
                script.on('message', on_message)
                Log.info('Load script name: ' + full_script_name)
                script.load()
        
        Log.info('Waiting for JavaScript...')
        print('--------------------------------------------------')
        sys.stdin.read()

    except Exception as e:
        Log.error(repr(e))
