# Send notificaion email
import smtplib
import hashlib
import time
from sniffy import constants as C

class EmailNotification:
  def __init__(self, email):
    self.email = email

  def send_mail(self, user, counter, data):
    data.t = time.strftime("%Z - %Y/%m/%d, %H:%M:%S", time.localtime(data.t))
    FROM = 'root@' + C.THIS_HOST
    TO = self.email
    SUBJECT = 'Possible abuser on %s' % C.THIS_HOST
    TEXT = """\
Possible abuser discovered on %s with the following details:
User name: %s
Source IP: %s
Destination IP: %s
Time: %s
Request Path: %s
Method: %s
Payload: %s
Requests counted: %s
""" % (C.THIS_HOST,
       user,
       data.src_ip,
       data.dst_ip,
       data.t,
       data.path,
       data.method,
       data.payload,
       counter)

    message = """\
From: %s
To: %s
Subject: %s

%s
""" % (FROM, TO, SUBJECT, TEXT)

    # Send the mail
    server = smtplib.SMTP(C.THIS_HOST)
    server.sendmail(FROM, TO, message)
    server.quit()
