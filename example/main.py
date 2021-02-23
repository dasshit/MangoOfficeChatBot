from uuid import uuid4
from os import environ
from MangoBot import MangoBot

environ.setdefault('login', 'LOGIN')
environ.setdefault('password', 'PASSWORD')


def test(self, event):
    self.logger.info(event)
    self.factoryBasicText(event.message.account, '{}-{}'.format(event.message.payload.body, uuid4()))


def test2(self, event):
    self.sendSms(event.message.payload.body, f'Test SMS - {event.message.account}')


def test3(self, event):
    text = f'''Event: SMS delivery status

User: {self.findUserById(event.message.sender)}
To number: {event.message.payload.number}

Status: {event.message.payload.status}

Text: {event.message.payload.body}'''
    self.sendBasicText(chat_id="mango@telecom.favorite.service", text=text)


def test4(self, event):
    text = f'''Event: SMS delivery status

User: {self.findUserById(event.fromUser)}
To number: {event.message.payload.number}

Status: {event.message.payload.status}

Text: {event.message.payload.body}'''
    self.sendBasicText(chat_id="mango@telecom.favorite.service", text=text)


t = MangoBot(login=environ.get('login'), password=environ.get('password'))

for _ in range(0, 5):
    t.addEventHandler('401', str(uuid4()), test)
    t.addEventHandler('401', r'\d{11}', test2)
    t.addEventHandler('808', r'\d{11}', test2)

t.addEventHandler('401', '', test3)
t.addEventHandler('402', '', test4)

if __name__ == "__main__":
    try:
        t.execute()
        t.endlessCycle()
    except Exception as error:
        t.logger.exception(error)
