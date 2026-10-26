"""Run only inside a disposable Docker Linux container as root.

The service manager is a recording fake; account creation, filesystem layout,
the ordinary-user file process and its private HTTP endpoint are real.
"""
import os, pathlib, subprocess, json, socket, http.client, time, signal, shutil

assert pathlib.Path('/.dockerenv').is_file() and os.geteuid() == 0, 'disposable root Docker container required'
private = pathlib.Path('/root/private-client'); private.mkdir(mode=0o700)
binary = str(private/'calabi')
previous=os.environ.get('CALABI_PREVIOUS_CLIENT')
shutil.copyfile(previous or '/test/p2-calabi-linux',binary); os.chmod(binary,0o755)
fake = pathlib.Path('/tmp/service-tools'); fake.mkdir()
manager = fake/'systemctl'
manager.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >>/tmp/systemctl.calls\ncase "$1" in is-enabled|is-active) test ! -f /tmp/disabled ;; *) exit 0 ;; esac\n')
manager.chmod(0o755)
os.environ['PATH'] = str(fake)+':'+os.environ['PATH']
# Exercise host installation instead of Docker's foreground-daemon adaptation.
os.environ['CALABI_IN_CONTAINER'] = '0'
pathlib.Path('/run/systemd/system').mkdir(parents=True, exist_ok=True)
shared_bin=pathlib.Path('/usr/local/bin')
shared_bin.chmod(0o751)
def cli(*args, **kwargs):
    return subprocess.run([binary, 'mesh','files','service',*args],check=kwargs.pop('check', True),capture_output=True,text=True,timeout=45,**kwargs)
subprocess.run([binary,'daemon','install','--system'],check=True,timeout=45)
if previous:
    shutil.copyfile('/test/p2-calabi-linux',binary)
    cli('refresh')
assert pathlib.Path('/etc/systemd/system/calabi.service').exists(), 'daemon install did not register its unit'
unit = pathlib.Path('/etc/systemd/system/calabi-files.service').read_text()
assert 'User=calabi-files\n' in unit and 'After=network.target calabi.service' in unit
assert 'RuntimeDirectoryMode=0700' in unit and 'NoNewPrivileges=true' in unit
assert shared_bin.stat().st_mode & 0o777 == 0o751, 'installer changed a shared system directory mode'
cli('install','--console','http://127.0.0.1:7500')
profile=json.loads(pathlib.Path('/etc/calabi-files/calabi-files.json').read_text())
assert profile['console']=='http://127.0.0.1:7500' and profile['state_dir']=='/var/lib/calabi-files'
cli('install','--console','http://127.0.0.1:7400')
helper='/usr/local/bin/calabi-files-helper'
assert helper in unit, 'unit must use the SELinux executable bin path'
assert subprocess.run(['runuser','-u','calabi-files','--',helper,'version'],capture_output=True).returncode==0
assert subprocess.run(['runuser','-u','calabi-files','--',binary,'version'],capture_output=True).returncode!=0, 'private daemon directory was opened to file user'
assert not list(pathlib.Path('/var/lib/calabi-files').rglob('receive-settings.json')), 'install must not opt in'
assert cli('web-url',check=False).returncode != 0, 'key must not be created by root before the service starts'
assert not list(pathlib.Path('/var/lib/calabi-files').rglob('browser-access-key')), 'management lookup created private state'
assert subprocess.run([binary,'mesh','files','service','run'],capture_output=True).returncode != 0, 'root file process accepted'
# Upgrade retains the profile and a deliberate disabled/stopped service.
pathlib.Path('/tmp/disabled').touch()
pathlib.Path('/tmp/systemctl.calls').write_text('')
cli('refresh')
calls = pathlib.Path('/tmp/systemctl.calls').read_text()
assert 'restart calabi-files' not in calls and 'enable calabi-files' not in calls
runtime = pathlib.Path('/run/calabi-files-7400'); runtime.mkdir(mode=0o700)
import pwd
account = pwd.getpwnam('calabi-files'); os.chown(runtime, account.pw_uid, account.pw_gid)
log = open('/tmp/file-service.log','w+')
process = subprocess.Popen(['runuser','-u','calabi-files','--','env','XDG_CONFIG_HOME=/var/lib/calabi-files/.config',helper,'mesh','files','service','run'],stdout=log,stderr=log,start_new_session=True)
endpoint = str(runtime/'web.sock')
class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX); self.sock.settimeout(3); self.sock.connect(endpoint)
def request(path,method='GET',body=None,key=None,origin='http://127.0.0.1:7400'):
    conn=UnixHTTP('127.0.0.1:7400')
    headers={'Origin':origin}
    if key: headers['Cookie']='calabi_file_browser='+key
    conn.request(method,path,body,headers); response=conn.getresponse(); data=response.read(); status=response.status; headers=dict(response.getheaders()); conn.close();return status,data,headers
try:
    for _ in range(100):
        if pathlib.Path(endpoint).exists():break
        assert process.poll() is None, 'ordinary-user service exited'
        time.sleep(.05)
    status,html,_=request('/')
    assert status==200 and b'<base href="/file-service/">' in html
    assert b'/file-service/file-web-config.js' in html
    key=pathlib.Path('/var/lib/calabi-files/.config/Calabi/file-agent/browser-access-key').read_text()
    assert request('/file-web/action','POST','{"action":"snapshot"}')[0]==401
    assert request('/file-web/session','POST',json.dumps({'key':key}),origin='http://evil.example')[0]==403
    status,_,headers=request('/file-web/session','POST',json.dumps({'key':key}))
    assert status==200 and 'Path=/file-service/file-web/' in headers['Set-Cookie']
    status,data,_=request('/file-web/action','POST','{"action":"snapshot"}',key)
    snapshot=json.loads(data)
    assert status==200 and snapshot['service']['managed'] and not snapshot['service']['receiving_requested']
    assert not snapshot['available'], 'offline must not be reported available'
    assert not snapshot['sources'] and not snapshot['jobs']
    assert request('/file-web/action','POST','{"action":"service_settings","auto_save":true}',key)[0]==200
    assert request('/file-web/action','POST','{"action":"receiving","enabled":false}',key)[0]==200
    saved=pathlib.Path('/var/lib/calabi-files/.config/Calabi/file-agent/receive-settings.json')
    settings=json.loads(saved.read_text())
    assert not settings['receiving'] and settings['auto_save'] and saved.stat().st_uid==account.pw_uid
    log.flush(); assert key not in pathlib.Path('/tmp/file-service.log').read_text(), 'private browser key leaked to journal'
finally:
    os.killpg(process.pid,signal.SIGTERM)
    process.wait(timeout=10)
cli('reset-web-key')
assert not pathlib.Path('/var/lib/calabi-files/.config/Calabi/file-agent/browser-access-key').exists()
cli('uninstall')
assert not pathlib.Path('/etc/systemd/system/calabi-files.service').exists()
assert pathlib.Path('/var/lib/calabi-files/.config/Calabi/file-agent/receive-settings.json').exists()
assert pathlib.Path('/etc/calabi-files/calabi-files.json').exists()
subprocess.run([binary,'daemon','uninstall','--system'],check=True,timeout=45)
assert not pathlib.Path('/etc/systemd/system/calabi.service').exists()
print('PASS: install, preserve disabled state on upgrade, ordinary-user runtime, private browser auth, offline management, reception default, non-destructive uninstall')
