from uuid import uuid4
from os import environ
from MangoBot import MangoBot

environ.setdefault('login', 'LOGIN')

environ.setdefault('password', 'PASSWORD')


def test(self, event):
    self.logger.info(event)
    self.factoryBasicText(event.message.account, '{}-{}'.format(event.message.payload.body, uuid4()))


def test2(self, event):
    self.sendSms(event.message.payload.body, 'Test SMS')


t = MangoBot(login=environ.get('login'), password=environ.get('password'))

for _ in range(0, 5):
    t.addEventHandler(str(uuid4()), test)
    t.addEventHandler(r'\d{11}', test2)

if __name__ == "__main__":
    try:
        t.execute()
        t.endlessCycle()
    except Exception as error:
        t.logger.exception(error)
