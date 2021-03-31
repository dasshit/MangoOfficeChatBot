from uuid import uuid4
from os import environ
from MangoBot import MangoBot

environ.setdefault('login', '')  # Здесь указываем логин
environ.setdefault('password', '')  # Пароль


def test(self, event):  # Тестовая функция для обработки входящих сообщений (Эхо бот)
    self.logger.info(event)
    self.factoryBasicText(event.message.account, '{}-{}'.format(event.message.payload.body, uuid4()))


def test2(self, event):  # Отправка СМС
    self.sendSms(event.message.payload.body, f'Test SMS - {event.message.account}')


def test3(self, event):  # Обработка события о статусе СМС и отправка сообщения в Избранное
    text = f'''Event: SMS delivery status

User: {self.findUserById(event.message.sender)}
To number: {event.message.payload.number}

Status: {event.message.payload.status}

Text: {event.message.payload.body}'''
    self.sendBasicText(chat_id="mango@telecom.favorite.service", text=text)


def test4(self, event):  # Обработка события о статусе СМС и отправка сообщения в Избранное
    text = f'''Event: SMS delivery status

User: {self.findUserById(event.fromUser)}
To number: {event.message.payload.number}

Status: {event.message.payload.status}

Text: {event.message.payload.body}'''
    self.sendBasicText(chat_id="mango@telecom.favorite.service", text=text)


bot = MangoBot(login=environ.get('login'), password=environ.get('password'))  # Создаем экземпляр бота

for _ in range(0, 5):  # Добавляем созданные функции как обработчики
    bot.addEventHandler('401', str(uuid4()), test)
    bot.addEventHandler('401', r'\d{11}', test2)
    bot.addEventHandler('808', r'\d{11}', test2)

bot.addEventHandler('401', '', test3)
bot.addEventHandler('402', '', test4)

if __name__ == "__main__":
    try:
        bot.execute()
        bot.endlessCycle()
    except Exception as error:
        bot.logger.exception(error)
