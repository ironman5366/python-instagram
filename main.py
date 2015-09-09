import tkFileDialog
from Tkinter import *
import easygui
import time
import os
import threading
import requests
import hmac
import random
import uuid
import urllib
import json
import hashlib
import time

try:
    # python 2
    urllib_quote_plus = urllib.quote
except:
    # python 3
    urllib_quote_plus = urllib.parse.quote_plus

def _generate_signature(data):
    return hmac.new('b4a23f5e39b5929e0666ac5de94c89d1618a2916'.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()


def _generate_user_agent():
    resolutions = ['720x1280', '320x480', '480x800', '1024x768', '1280x720', '768x1024', '480x320']
    versions = ['GT-N7000', 'SM-N9000', 'GT-I9220', 'GT-I9100']
    dpis = ['120', '160', '320', '240']

    ver = random.choice(versions)
    dpi = random.choice(dpis)
    res = random.choice(resolutions)

    return (
        'Instagram 4.{}.{} '
        'Android ({}/{}.{}.{}; {}; {}; samsung; {}; {}; smdkc210; en_US)'
    ).format(
        random.randint(1, 2),
        random.randint(0, 2),
        random.randint(10, 11),
        random.randint(1, 3),
        random.randint(3, 5),
        random.randint(0, 5),
        dpi,
        res,
        ver,
        ver,
    )


class InstagramSession(object):

    def __init__(self):
        self.guid = str(uuid.uuid1())
        self.device_id = 'android-{}'.format(self.guid)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': _generate_user_agent()})

    def login(self, username, password):

        data = json.dumps({
            "device_id": self.device_id,
            "guid": self.guid,
            "username": username,
            "password": password,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        print(data)

        sig = _generate_signature(data)

        payload = 'signed_body={}.{}&ig_sig_key_version=4'.format(
            sig,
            urllib_quote_plus(data)
        )

        r = self.session.post("https://instagram.com/api/v1/accounts/login/", payload)
        r_json = r.json()
        print(r_json)

        if r_json.get('status') != "ok":
            return False

        return True

    def upload_photo(self, filename):
        data = {
            "device_timestamp": time.time(),
        }
        files = {
            "photo": open(filename, 'rb'),
        }

        r = self.session.post("https://instagram.com/api/v1/media/upload/", data, files=files)
        r_json = r.json()
        print(r_json)

        return r_json.get('media_id')

    def configure_photo(self, media_id, caption):
        data = json.dumps({
            "device_id": self.device_id,
            "guid": self.guid,
            "media_id": media_id,
            "caption": caption,
            "device_timestamp": time.time(),
            "source_type": "5",
            "filter_type": "0",
            "extra": "{}",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        print(data)

        sig = _generate_signature(data)

        payload = 'signed_body={}.{}&ig_sig_key_version=4'.format(
            sig,
            urllib_quote_plus(data)
        )

        r = self.session.post("https://instagram.com/api/v1/media/configure/", payload)
        r_json = r.json()
        print(r_json)

        if r_json.get('status') != "ok":
            return False

        return True
processes = []
num = 0
def main():
	def get_file():
		print "in get_file function"
		root = Tk()
		root.withdraw()
		filepath = tkFileDialog.askopenfilename() #Get the image name
		return filepath
	def upload(filepath, caption, user, password, context):
		print "Filepath is "+filepath 
		insta = InstagramSession()
		print "InstagramSession started"
		if user == None and password == None:
			authfields = ["Username:", "Password:"]
			auth = easygui.multenterbox("Authentication", "Please enter a username and password.", authfields)
			user = auth[0]
			USERNAME = auth[0]
			password = auth[1]
			PASSWORD = auth[1]
		if user == None:
			USERNAME = easygui.enterbox("Please enter a username:")
		else:
			USERNAME = user
		if password == None:
			PASSWORD = easygui.enterbox("Please enter a password:")
		else:
			PASSWORD = password
		if insta.login(USERNAME, PASSWORD):
			print "Inside login"
			media_id = insta.upload_photo(filepath)
			print "media id"
			if media_id is not None:
				if caption == None:
					description = easygui.enterbox("Please enter a description of the image:")
				else:
					description = str(caption)
				insta.configure_photo(media_id, description)
				if context != "scheduled":
					main()
				else:
					pass
	def wait(sleeptime, filepath, description, username, password):
		strsleep = str(sleeptime)
		print "Sleeptime is "+strsleep
		for item in range(0, sleeptime):
			print str(item)
			time.sleep(1)
		upload(filepath, description, username, password, "scheduled")
	def new_schedule():
		filepath = get_file()
		timeenters = ["Days", "Hours", "Minutes", "Seconds"]
		stime = easygui.multenterbox("Scheduler", "Please specify a time", timeenters)
		days = stime[0]
		hours = stime[1]
		minutes= stime[2]
		seconds = stime[3]
		description = easygui.enterbox("Please enter a description of the image")
		days = int(days)*24
		hours = int(days)+int(hours)
		minutes = hours*60+int(minutes)
		seconds = minutes*60+int(seconds)
		isauth = os.path.isfile("auth.txt")
		if isauth == True:
			authfile = open("auth.txt").read().split('\n')
			print authfile
			username = authfile[0]
			password = authfile[1]
		else:
			accountfields = ["Username:", "Password:"]
			userpass = easygui.multenterbox("Authentication", "Please enter the required information.", accountfields)
			username = userpass[0]
			password = userpass[1]
		p = threading.Thread(target=wait, args=(seconds, filepath, description, username, password))
		processes.append(p)
		p.start()
#		processfile.close()
		main()
	def quick_upload():
		file = get_file()
		isauth = os.path.isfile("auth.txt")
		caption = easygui.enterbox("Please enter a description of the image.")
		if isauth == True:
			fields = open("auth.txt").read().split('\n')
			user = fields[0]
			password = fields[1]
		else:
			accountfields = ["Username:", "Password:"]
			userpass = easygui.multenterbox("Authentication", "Please enter the required information.", accountfields)
			username = userpass[0]
			password = userpass[1]
		upload(file, caption, user, password, "quick")
	def account_change():
		accountfields = ["Username:", "Password:"]
		userpass = easygui.multenterbox("Edit Stored Account", "Please enter the required information.", accountfields)
		authfile = open("auth.txt", 'w')
		authfile.write(userpass[0]+'\n')
		authfile.write(userpass[1])
		main()
	def maingui():
		if os.path.isfile("auth.txt") == True:
			accountstatus = ("Change account")
		else:
			accountstatus = ("Sign into account")
		choices = ["Quick Upload", "Add Upload",accountstatus]
		mainchoices = easygui.choicebox(msg="Welcome to the instagram uploader. Please make a choice.", title="Welcome", choices=choices)
		if mainchoices == choices[0]:
			quick_upload()
		elif mainchoices == choices[1]:
			new_schedule()
		elif mainchoices == accountstatus:
			account_change()
	maingui()
main()
