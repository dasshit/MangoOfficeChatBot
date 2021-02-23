from requests import post, Response
from time import sleep
from re import search
import random as rnd
from base64 import b64encode
from loguru import logger
from uuid import uuid4
from typing import *
from datetime import datetime
from re import match
from multiprocessing import Process
from configReader import config, de__json
from os import environ

requestLog: str = config.logStrings.requestLog
failedResponseLog: str = config.logStrings.failedResponseLog
successResponseLog: str = config.logStrings.successResponseLog


def localIdGenerator() -> str:
    return str(rnd.randint(10000000000000000000000000000000, 99999999999999999999999999999999))


def messageCreate(chat_id: str, payload: dict, messageType: str, replyTo: str = None):
    data = {"localId": localIdGenerator(), "payload": payload, "to": chat_id, "type": messageType}
    if replyTo:
        data.update({("replyTo", replyTo)})
    return data


def eventCheck(event, purposedEventType):
    if event.type in ['401', '405', '808']:
        if event.message.type != 'sms':
            return True if [event.type == purposedEventType, event.message.outgoing is False,
                            event.message.type == 'text',
                            event.message.account != 'mango@telecom.service'].count(True) == 4 else False
        else:
            return True if event.type == purposedEventType else False
    else:
        return True if event.type == purposedEventType else False


class MangoBot:
    __slots__ = ['authUrl', 'mainUrl', 'apiVksUrl', 'token', 'lastSid', 'UserAgent', 'login', 'password',
                 'basic_token', 'fsUrl', 'roster', 'deviceId', 'header', 'fsHeader', 'logger', 'handlersDict',
                 'authToken', 'uploadPath', 'clientApiUrl', 'clientApiKey', 'addressBookUrl', 'messageFactoryBuffer',
                 'RmqCallbackFunction', 'webchatFactoryBuffer']

    def __init__(self, login: str = environ.get('login'), password: str = environ.get('password'),
                 authUrl: str = config.urls.authUrl, mainUrl: str = config.urls.chatApiUrl,
                 fsUrl: str = config.urls.chatFsUrl, apiVksUrl: str = config.urls.apiVksUrl,
                 clientApiUrl: str = config.urls.clientApiUrl, addressBookUrl: str = config.urls.addressBookUrl,
                 UserAgent: str = config.userAgent.format(uuid4()), basic_token: str = None,
                 lastSid: str = None, deviceId: str = None, roster: tuple[Any, Any] = None,
                 header: dict = None, fsHeader: dict = None):
        from loguru import logger
        self.authUrl: str = authUrl
        self.mainUrl: str = mainUrl
        self.clientApiUrl: str = clientApiUrl
        self.fsUrl: str = fsUrl
        self.apiVksUrl: str = apiVksUrl
        self.addressBookUrl: str = addressBookUrl
        self.lastSid: str = lastSid
        self.UserAgent: str = UserAgent
        self.login: str = login
        self.password: str = password
        self.authToken: Optional[str, None] = None
        self.clientApiKey: Optional[str, None] = None
        self.basic_token: str = basic_token
        self.roster: tuple[Any, Any] = roster
        self.deviceId: str = deviceId
        self.header: dict = header
        self.fsHeader: dict = fsHeader
        self.logger: logger = logger
        self.uploadPath: str = '/upload_chunk.php?toAccount={}&localId={}'
        self.messageFactoryBuffer: list[dict] = []
        self.webchatFactoryBuffer: list[dict] = []
        self.handlersDict: list[dict] = []
        self.RmqCallbackFunction: list = []
        self.coldStart()

    def __str__(self):
        return 'User: {}, DeviceId: {}'.format(self.login, self.deviceId)

    def firstStepHash(self):
        self.basic_token: str = f"Basic {b64encode(f'{self.login}:{self.password}'.encode('ascii')).decode('ascii')}"

    def secondStepHash(self, account: str, hashing: str):
        self.header: dict = {
            'Authorization': f"Basic {b64encode(f'{account}:{hashing}'.encode('ascii')).decode('ascii')}",
            'User-Agent': self.UserAgent
        }

    def _request(self, *args, url: str = config.urls.chatApiUrl, headers: dict = ()) -> tuple[Any, Any]:
        if not headers:
            headers = self.header
        if self.logger is not None:
            self.logger.info(requestLog.format(f'{url}{args[0]}', args[1]))
        result: Response = post(f'{url}{args[0]}', headers=headers, json=args[1], timeout=(999, 30))
        classDeJson: tuple[Any, Any] = de__json(result.text, args[0])
        if self.logger is not None:
            if result.status_code != 200:
                self.logger.exception(failedResponseLog.format(result.status_code, result.headers, result.text))
            else:
                self.logger.info(successResponseLog.format(result.status_code, result.headers))
        if args[0] == 'pollEvents':
            self.lastSid: str = classDeJson.data.lastSid
        else:
            try:
                for message in classDeJson.data:
                    self.lastSid: str = message.sid
            except Exception as error:
                self.logger.debug(error)
        return classDeJson

    def _request_fs(self, *args):
        if self.logger is not None:
            self.logger.info(requestLog.format(f'{self.fsUrl}{args[0]}', self.fsHeader))
        result: Response = post(f'{self.fsUrl}{args[0]}', headers=self.fsHeader, data=args[1])
        if self.logger is not None:
            if result.status_code != 200:
                self.logger.exception(failedResponseLog.format(result.status_code, result.headers, result.text))
            else:
                self.logger.info(successResponseLog.format(result.status_code, result.headers))
        return de__json(result.text, args[0])

    def authVpbx(self):
        self.authToken: str = self._request('auth/vpbx', {
            "app": "MT.Mobile", "username": self.login, "password": self.password, "device_id": localIdGenerator(),
            "checkParams": {
                "InsufficientFunds": 1
            }
        }, url=self.authUrl).auth_token

    def clientApiGenerate(self):
        self.clientApiKey: str = self._request('vpbx/v1/api_key/generate', {
            'auth_token': self.authToken
        }, url=self.clientApiUrl).api_key

    def clientApiCallback(self, fromNumber: str, toNumber: str) -> tuple[Any, Any]:
        if not self.clientApiKey:
            self.clientApiGenerate()
        return self._request('vpbx/v1/callback', {
            "auth_token": self.authToken,
            "to": toNumber,
            "api_key": self.clientApiKey,
            "from": fromNumber
        }, url=self.clientApiUrl)

    def register(self):
        self.firstStepHash()
        self.header = {'Authorization': self.basic_token, 'User-Agent': self.UserAgent, 'X-Api-Version': '2'}
        data = {"deviceId": localIdGenerator(), "deviceName": self.UserAgent, "os": "Ubuntu 16 Server"}
        result = self._request('register', data).data
        for _ in range(0, 10):
            try:
                self.secondStepHash(result.account, result.hash)
                break
            except (KeyError, AttributeError):
                sleep(3)
                result = self._request('register', data).data
        self.deviceId = data['deviceId']
        del (data, result)

    def startSession(self):
        result = self._request('startSession', {
            "model": self.UserAgent, "os": "Mac OS Big Sur", "rawPermissions": True, "status": "3", "textStatus": ""
        })
        self.lastSid = result.data.lastSid
        del result

    def coldStart(self):
        for func in [self.authVpbx, self.clientApiGenerate, self.register, self.startSession]:
            func()

    def execute(self, get_data: tuple[str] = ("devices", "vcards")) -> tuple[Any, Any]:
        result = self._request('execute', {"from_ts": 0, "get-data": get_data}).data
        self.roster = result.vcards
        return result

    def removeDevice(self, deviceID: str = None) -> tuple[Any, Any]:
        return self._request('removeDevice', {"deviceId": deviceID})

    def findUserById(self, user: str) -> tuple[Any, Any]:
        for rost in self.roster:
            if user == rost.account:
                del user
                return rost.vcard.firstName, rost.vcard.lastName
        raise ValueError(f'User {user} not found in roster')

    def findUserByName(self, name: str) -> str:
        for user in self.roster:
            try:
                if search(user.vcard.mangoExtra.general.name.replace('ё', 'е'), name):
                    return user.account
            except (KeyError, AttributeError):
                pass
        raise NameError(f'User not found, name: {name}')

    def getCompanyByPhone(self, number: str) -> tuple[Any, Any]:
        return self._request('getCompanyByPhone', {"number": number})

    def callsGet(self, toId: str, limit: int = 100) -> tuple[Any, Any]:
        return self._request('calls/get', {"toId": toId, "limit": limit})

    def callsRecent(self, limit: int = 100) -> tuple[Any, Any]:
        return self._request('calls/recent', {"limit": limit})

    def callsHistory(self, numbers: list[str], limit: int = 100) -> tuple[Any, Any]:
        return self._request('calls/history', {"numbers": numbers, "limit": limit})

    def callsSearch(self, query: str, numbers: list[str] = ('', ''),
                    onlyMissed: bool = False, toId: str = None, limit: int = 50) -> tuple[Any, Any]:
        if toId is None:
            toId = self.lastSid
        return self._request('calls/search', {
            "query": query, "numbers": numbers, "onlyMissed": onlyMissed, "toId": toId, "limit": limit
        })

    def callsRemove(self, sid: str) -> tuple[Any, Any]:
        return self._request('calls/remove', {"sid": sid})

    def messageHistory(self, talkers: str, toId: str = None,
                       limit: int = 20, latest: int = 1, linksFilter: bool = False) -> tuple[Any, Any]:
        if toId is None:
            toId = self.lastSid
        return self._request('message/history', {
            "linksFilter": linksFilter, "latest": latest,
            "toId": toId, "limit": limit, "talkers": [{"account": talkers}]
        })

    def messageLinksHistory(self, talkers: str,
                            limit: int = 300, latest: int = 1, linksFilter: bool = False) -> tuple[Any, Any]:
        return self._request('message/history', {
            "linksFilter": linksFilter, "latest": latest, "limit": limit, "talkers": [{"account": talkers}]
        })

    def messageNotifyDelivered(self, chat_id: str, sid: str) -> tuple[Any, Any]:
        return self._request('message/history', {"messages": [{"sid": sid, "account": chat_id}]})

    def messageNotifyRead(self, account: str, sid: str) -> tuple[Any, Any]:
        return self._request('message/notifyRead', {'account': account, 'sid': sid})

    def messageNotifyTyping(self, chat_id: str, finished: bool = False) -> tuple[Any, Any]:
        return self._request('message/notifyTyping', {'finished': finished, 'to': chat_id})

    def messageFactoryAddToBuffer(self, chat_id: str, payload: dict, messageType: str, replyTo: str = None):
        self.messageFactoryBuffer.append(messageCreate(chat_id, payload, messageType, replyTo))

    def messageFactoryClearBuffer(self):
        self.messageFactoryBuffer = []

    def messageFactorySend(self) -> tuple[Any, Any]:
        result: tuple[Any, Any] = self._request('message/send', {"messages": self.messageFactoryBuffer})
        self.messageFactoryClearBuffer()
        return result

    def messageSend(self, chat_id: str, payload: dict, messageType: str, replyTo: str = None) -> tuple[Any, Any]:
        return self._request('message/send', {"messages": [messageCreate(chat_id, payload, messageType, replyTo)]})

    def sendBasicText(self, chat_id: str, text: str) -> tuple[Any, Any]:
        return self.messageSend(chat_id=chat_id, payload={"body": text}, messageType="text")

    def factoryBasicText(self, chat_id: str, text: str):
        self.messageFactoryAddToBuffer(chat_id=chat_id, payload={"body": text}, messageType="text")

    def sendGeoPosition(self, chat_id: str, lat: float, long: float, name: str, address: str) -> tuple[Any, Any]:
        return self.messageSend(chat_id=chat_id, payload={
            "lat": lat, "long": long, "name": name, "address": address
        }, messageType="geoposition")

    def factoryGeoPosition(self, chat_id: str, lat: float, long: float, name: str, address: str):
        self.messageFactoryAddToBuffer(chat_id=chat_id, payload={
            "lat": lat, "long": long, "name": name, "address": address
        }, messageType="geoposition")

    def sendContact(self, chat_id: str, firstName: str, lastName: str, sipIds: list[str],
                    emails: list[str], phones: list[dict[str]]) -> tuple[Any, Any]:
        return self.messageSend(chat_id=chat_id, payload={
            "lastName": lastName, "firstName": firstName, "sipIds": sipIds, "emails": emails, "phones": phones
        }, messageType="contact")

    def factoryContact(self, chat_id: str, firstName: str, lastName: str, sipIds: list[str],
                       emails: list[str], phones: list[dict[str]]):
        self.messageFactoryAddToBuffer(chat_id=chat_id, payload={
            "lastName": lastName, "firstName": firstName, "sipIds": sipIds, "emails": emails, "phones": phones
        }, messageType="contact")

    def sendSms(self, number: str, text: str) -> tuple[Any, Any]:
        return self._request('message/sendSms', {"localId": localIdGenerator(), "text": text, "number": number})

    def messageRemove(self, chat_id: str, forAll: bool, messages) -> tuple[Any, Any]:
        if isinstance(messages, str):
            m_list = [messages]
        elif isinstance(messages, list):
            m_list = messages
        else:
            raise TypeError(
                'Argument "messages" type should be list[str] or str, current type: {}'.format(type(messages)))
        del messages
        return self._request('message/remove', {"account": chat_id, "forAll": forAll, "messages": m_list})

    def chatCreateChannel(self, topic: str, description: str, channelType: str, members: list[str]) -> tuple[Any, Any]:
        return self._request('chat/create', {
            "channelType": channelType, "localId": localIdGenerator(), "isChannel": True,
            "topic": topic, "description": description, "members": members
        })

    def chatCreateGroup(self, topic: str, description: str, members: list[str]) -> tuple[Any, Any]:
        return self._request('chat/create', {
            "localId": localIdGenerator(), "topic": topic, "description": description, "members": members
        })

    def chatEdit(self, chat_id: str, topic: str, description: str) -> tuple[Any, Any]:
        return self._request('chat/edit', {"account": chat_id, "topic": topic, "description": description})

    def chatModify(self, chat_id: str, add: list[str], remove: list[str]) -> tuple[Any, Any]:
        return self._request('chat/modify', {"account": chat_id, "add": add, "remove": remove})

    def chatSetUserAdminRole(self, chat_id: str, user: str) -> tuple[Any, Any]:
        return self._request('chat/updateMember', {"account": chat_id, "roles": [{"account": user, "role": "admin"}]})

    def chatUnsetUserAdminRole(self, chat_id: str, user: str) -> tuple[Any, Any]:
        return self._request('chat/updateMember', {"account": chat_id, "roles": [{"account": user, "role": "member"}]})

    def chatMute(self, chat_id: str, mute: bool) -> tuple[Any, Any]:
        return self._request('chat/mute', {"account": chat_id, "mute": mute})

    def chatPin(self, chat_id: str, pinned: bool) -> tuple[Any, Any]:
        return self._request('chat/pin', {"account": chat_id, "pinned": pinned})

    def chatRemove(self, chat_id: str) -> tuple[Any, Any]:
        return self._request('chat/remove', {"account": chat_id})

    def chatRemoveChannel(self, chat_id: str) -> tuple[Any, Any]:
        return self._request('chat/removeChannel', {"account": chat_id})

    def webchatHistoryGet(self, talkers: list[dict], toId: str, limit: int, latest: int = 1) -> tuple[Any, Any]:
        return self._request('webchat/history/get', {
            "talkers": talkers, "toId": toId, "limit": limit, "latest": latest
        })

    def webchatHistorySync(self, sinceId: str, limit: int) -> tuple[Any, Any]:
        return self._request('webchat/history/get', {"sinceId": sinceId, "limit": limit})

    def webchatTakeOver(self, chat_id: str) -> tuple[Any, Any]:
        return self._request('webchat/takeover', {"account": chat_id})

    def webchatNotifyRead(self, chat_id: str, sid: str) -> tuple[Any, Any]:
        return self._request('webchat/notifyRead', {
            "account": chat_id, "sid": sid
        })

    def webchatNotifyTyping(self, chat_id: str, finished: bool) -> tuple[Any, Any]:
        return self._request('webchat/notifyRead', {
            "to": chat_id, "finished": finished
        })

    def webchatSend(self, chat_id: str, payload: dict, messageType: str) -> tuple[Any, Any]:
        return self._request('webchat/send', {"messages": [messageCreate(chat_id, payload, messageType, None)]})

    def webchatFactoryAddToBuffer(self, chat_id: str, payload: dict, messageType: str, replyTo: str = None):
        self.webchatFactoryBuffer.append(messageCreate(chat_id, payload, messageType, replyTo))

    def webchatFactoryBasicText(self, chat_id: str, text: str):
        self.webchatFactoryAddToBuffer(chat_id=chat_id, payload={"body": text}, messageType="text")

    def webchatFactoryClearBuffer(self):
        self.webchatFactoryBuffer = []

    def webchatFactorySend(self) -> tuple[Any, Any]:
        result: tuple[Any, Any] = self._request('webchat/send', {"messages": self.webchatFactoryBuffer})
        self.webchatFactoryClearBuffer()
        return result

    def bookSrcList(self, product_id: str):
        return self._request('src/list', {"product_id": product_id},
                             url=self.addressBookUrl, headers={"X-AUTH-TOKEN": self.authToken})

    def bookGetByPhone(self, product_id: str, sources: list, query: list):
        return self._request('contacts/get-by-phone', {
            "product_id": product_id, "sources": sources, "query": query, "version": "v2"
        }, url=self.addressBookUrl, headers={"X-AUTH-TOKEN": self.authToken})

    def bookQuery(self, product_id: str, sources: list, query: list, limit_rows: int = 200, order: str = 'asc'):
        return self._request('contacts/get-by-phone', {
            "product_id": product_id, "limit_rows": limit_rows, "version": "v2",
            "query": query, "order": {"name": order}, "sources": sources
        }, url=self.addressBookUrl, headers={"X-AUTH-TOKEN": self.authToken})

    def pathFormat(self, sender: str, isFax: bool = False) -> str:
        return self.uploadPath.format(
            sender, localIdGenerator() + '&fax=1' if isFax else localIdGenerator())

    def openAndUploadFile(self, sender, final_json, isFax: bool) -> tuple[Any, Any]:
        if self.fsHeader is None:
            self.fsHeader = {
                'Authorization': self.token, 'Content-Type': 'application/octet-stream',
                'Content-Disposition': 'attachment; filename="{0}"'.format(final_json['filename'])
            }
        else:
            self.fsHeader['Content-Disposition'] = 'attachment; filename="{0}"'.format(final_json['filename'])
        with open('{}{}'.format(final_json['path'], final_json['filename']), 'rb') as f:
            return self._request_fs(self.pathFormat(sender, isFax=isFax), f.read())

    def uploadBytesIOFile(self, sender, file_io, isFax: bool) -> tuple[Any, Any]:
        if self.fsHeader is None:
            self.fsHeader = {
                'Authorization': self.token, 'Content-Type': 'application/octet-stream',
                'Content-Disposition': 'attachment; filename="{0}"'.format(file_io.name)
            }
        else:
            self.fsHeader['Content-Disposition'] = 'attachment; filename="{0}"'.format(file_io.name)
        return self._request_fs(self.pathFormat(sender, isFax=isFax), file_io)

    def createConfLink(self, tmValidUntil: float = datetime.now().timestamp() + 10800) -> tuple[Any, Any]:
        return self._request('vcmss/create_conf_link', {
            "tm_valid_until": tmValidUntil, "auth_token": self.authToken
        }, url=self.apiVksUrl)

    def addEventHandler(self, eventType: str, regexp: str, func):
        self.handlersDict.append({'eventType': eventType, 'regexp': regexp, 'function': func})

    def addRmqCallbackFunction(self, func):
        self.RmqCallbackFunction.append(func)

    def pollEvents(self) -> tuple[Any, Any]:
        return self._request('pollEvents', {
            'lastSid': self.lastSid
        })

    def matchFuncRegExpToEventBody(self, func: dict, event: tuple[Any, Any]):
        self.logger.info(f'Regexp: {func["regexp"]}, Function: {func["function"]}')
        if match(func['regexp'], event.message.payload.body):
            func['function'](self, event)
        else:
            self.logger.debug('Not matched')
            pass

    def eventHandle(self, event):
        self.logger.info(event)
        for func in self.handlersDict:
            if eventCheck(event, func['eventType']):
                self.matchFuncRegExpToEventBody(func, event)
            else:
                pass

    def endlessCycle(self):
        while True:
            try:
                for event in self.pollEvents().data.history:
                    self.eventHandle(event)
                if self.messageFactoryBuffer:
                    self.messageFactorySend()
                else:
                    pass
            except KeyboardInterrupt:
                logger.info('Trying to stop polling...')
                break
            except Exception as error:
                self.logger.exception(error)

    def start(self):
        for rmqFunction in self.RmqCallbackFunction:
            try:
                t = Process(target=rmqFunction, name=rmqFunction.__name__, args=(self,))
                t.start()
            except Exception as error:
                self.logger.exception(f'{rmqFunction.__name__} - {error}', exc_info=True)
