import config
from telebot import TeleBot, types
import database as db
from Manager import Manager
import time
import datetime
import secrets
import string
import json
import threading
import os
from zipfile import ZipFile

bot = TeleBot(token=config.BOT_TOKEN, parse_mode='Markdown', threaded=True) # Initializing Telegram Bot
mng = Manager()

def getNewProfileName(message: types.Message):
    '''
    Getting new profile's name from User

    Args:
        message (types.Message): User's message

    Check out register_next_step_handler from telebot documentation
    '''
    if message.text != '.q':
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        bot.send_message(message.chat.id, text=f'_Name of the new service:_ *{message.text}*')
        mng.profiles[message.text] = ()
        bot.send_message(message.chat.id, text="_Please send new profile's _*username* _or_ *.q* _to quit_")
        bot.register_next_step_handler(message=message, callback=getNewProfileUsername)
    else:
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')

def getNewProfileUsername(message: types.Message):
    '''
    Getting new profile's username from User

    Args:
        message (types.Message): User's message

    Check out register_next_step_handler from telebot documentation
    '''
    service_name = [serv for serv in list(mng.profiles.keys()) if len(mng.profiles[serv]) == 0][0]
    if message.text != '.q':
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        hashed_username = mng.encryptData(message.text, pswd_hash=mng.hashedMasterPswd)
        mng.profiles[service_name] += (hashed_username,)
        bot.send_message(message.chat.id, text='_Succesfully hashed new_ *username*.')
        bot.send_message(message.chat.id, text="_Please send new profile's _*password* _or_ *.q* _to quit or_ *.g* _to generate random._")
        bot.register_next_step_handler(message=message, callback=getNewProfilePassword)
    else:
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
        del mng.profiles[service_name]
    
def getNewProfilePassword(message: types.Message):
    '''
    Getting or generating new profile's password from User

    Args:
        message (types.Message): User's message

    Check out register_next_step_handler from telebot documentation
    '''
    service_name = [serv for serv in list(mng.profiles.keys()) if len(mng.profiles[serv]) == 1][0]
    if message.text == '.q':
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
        del mng.profiles[service_name]
        return
    elif message.text == '.g':
        generated_pswd = generatePassword()
        hashed_password = mng.encryptData(generated_pswd, pswd_hash=mng.hashedMasterPswd)
    else:
        hashed_password = mng.encryptData(message.text, pswd_hash=mng.hashedMasterPswd)
    bot.delete_message(message.chat.id, message.message_id)
    bot.delete_message(message.chat.id, message.message_id - 1)
    hashed_username = mng.profiles[service_name][0]
    mng.profiles[service_name] += (hashed_password,)
    bot.send_message(message.chat.id, text='_Succesfully hashed new_ *password*.')
    addNewProfile(service_name, hashed_username, hashed_password, message)

def addNewProfile(service_name: str, hashed_username: bytes, hashed_password: bytes, message):
    '''
    Adding new profile to db and Manager

    Args:
        service_name (str): Name of the profile's service
        hashed_username (bytes): Hashed username of the profile
        hashed_password (bytes): Hashed password of the profile
        message: Message object
    '''
    res = db.newProfile(service_name=service_name, username_hash=hashed_username.decode('utf-8'), password_hash=hashed_password.decode('utf-8'), database=mng.db)
    if res:
        bot.send_message(message.chat.id, text=f'_Succesfully created new profile:_ *{service_name}*')
    else:
        del mng.profiles[service_name]
        bot.send_message(message.chat.id, text=f'_Failed creating new profile:_ *{service_name}*')

def generatePassword(length: int = 16) -> str:
    '''
    Generating random password

    Args:
        length (int): Length of the password

    Returns:
        password (str): Randomly generated password
    '''

    if length < 6:
        length = 12
    uppercase_loc = secrets.choice(string.digits)  # random location of lowercase
    symbol_loc = secrets.choice(string.digits)  # random location of symbols
    lowercase_loc = secrets.choice(string.digits)  # random location of uppercase
    password = ""
    pool = string.ascii_letters + string.punctuation  # the selection of characters used
    for i in range(length):
        if i == uppercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_uppercase)
        elif i == lowercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_lowercase)
        elif i == symbol_loc:  # this is to ensure there is at least one symbol
            password += secrets.choice(string.punctuation)
        else:  # adds a random character from pool
            password += secrets.choice(pool)
    return password

def getMasterPassword(message: types.Message):
    '''
    Getting Master Password from User

    Args:
        message (types.Message): User's message

    Check out register_next_step_handler from telebot documentation
    '''
    if message.text != '.q':
        pswd = message.text
        with open(config.VERIFIER_FILE, 'r') as file:
            data = json.load(file)
        salt = data['salt'].encode('utf-8')
        verify = data['verify'].encode('utf-8')
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        if mng.checkMasterPassword(pswd, salt, verify):
            bot.send_message(message.chat.id, text='_Succesfully verified_ *master password.*')
            mng.hashedMasterPswd = mng.hashPassword(pswd, b'')
            mng.last_usage = datetime.datetime.now()
        else:
            bot.send_message(message.chat.id, text='*Master password* _is not verified. Try one more time._')

def verifyPassword(message: types.Message):
    '''
    Verifying password

    Args:
        message (types.Message): User's message
    '''
    if os.path.exists(config.VERIFIER_FILE):
        bot.send_message(message.chat.id, text="_Master Password currently is expired or not provided._\n\n_Send_ *master password* _in the next message or_ *.q* _to quit._")
        bot.register_next_step_handler(message, callback=getMasterPassword)
    else:
        bot.send_message(message.chat.id, text=f"_Couldn't find verify file. Create or paste new verify file.\n\n Expected filename:_ *{config.VERIFIER_FILE}*")

def deleteMessage(chat_id: int, message_id: int, timeout: int):
    '''
    Deleting message in chat after specified time

    Args:
        chat_id (int): ID of the chat from Telegram
        message_id (int): ID of the message from Telegram
        timeout (int): Amount of minutes to wait before deleting
    '''
    time.sleep(timeout * 60)
    bot.delete_message(chat_id, message_id)

def getProfileCreds(message: types.Message):
    '''
    Sending profile credentials to User

    Args:
        message (types.Message): User's message
    '''
    if message.text in list(mng.profiles.keys()):
        usr, pswd = mng.getProfile(message.text)
        msg = f'   _Profile_ *{message.text}:*\n'
        msg += f'   _Username_ : `{usr}`\n   _Password_ : `{pswd}`\n\n_Message will be deleted in {config.CREDS_DELETE_TIMEOUT} mins._'
        bot.send_message(message.chat.id, text=msg)
        threading.Thread(target=deleteMessage, args=(message.chat.id, message.message_id + 1, config.CREDS_DELETE_TIMEOUT,)).start()
    else:
        bot.send_message(message.chat.id, text=f'_Cannot find service with name_ *{message.text}*. _Try again_')

@bot.message_handler(commands=['start'])
def greetings(message: types.Message):
    '''
    Handling /start command from User
    
    Args:
        message (types.Message): User's message

    Getting message from decorator
    '''
    if message.chat.id not in config.ADMIN_IDS: # Auth on Telegram Level
        bot.send_message(message.chat.id, text="_Unfortunately you don't have access to this bot 🙅_")
    else:
        main_menu_markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
        add_profile_btn = types.KeyboardButton(text = 'Add Profile 🖊️')
        edit_profile_btn = types.KeyboardButton(text = 'Edit Profile ⚙️')
        delete_profile_btn = types.KeyboardButton(text = 'Delete Profile 🗑️')
        export_profiles_btn = types.KeyboardButton(text = 'Export Profiles 📤')
        manage_master_btn = types.KeyboardButton(text = 'Get Profile 🔑')
        main_menu_markup.add(add_profile_btn, edit_profile_btn, delete_profile_btn, export_profiles_btn, manage_master_btn)
        bot.send_message(message.chat.id, text='_Hello, use buttons from menu below to manage your passwords :)_', reply_markup=main_menu_markup)

@bot.message_handler(content_types=['text'])
def handle_menu(message: types.Message):
    '''
    Handling button messages from User

    Args:
        message (types.Message): User's message
    '''
    if message.chat.id not in config.ADMIN_IDS: # Auth on Telegram Level
        bot.send_message(message.chat.id, text="_Unfortunately you don't have access to this bot 🙅_")
    else:
        if message.text == 'Add Profile 🖊️':
            if mng.isPswdValid():
                bot.send_message(message.chat.id, text="_Please send new profile's _*service name* _or_ *.q* _to quit_")
                bot.register_next_step_handler(message=message, callback=getNewProfileName)
            else:
                verifyPassword(message)
        if message.text == 'Get Profile 🔑':
            if mng.isPswdValid():
                msg = '*Your profiles:\n*'
                for serv in list(mng.profiles.keys()):
                    msg += f" - _{serv}_\n"
                msg += '\n_Send service name in the following message..._'
                bot.send_message(message.chat.id, msg)
                bot.register_next_step_handler(message, getProfileCreds)
            else:
                verifyPassword(message)
        if message.text == 'Export Profiles 📤':
            if mng.isPswdValid():
                filename = f'data-{datetime.datetime.now().strftime("%d-%m-%y")}.zip'
                file = ZipFile(filename, 'w')
                file.write(config.DB_NAME)
                file.write(config.VERIFIER_FILE)
                file.close()
                bot.send_document(message.chat.id, data=open(filename, 'rb'))
            else:
                verifyPassword(message)         

def main():
    database = db.setUp()
    if database: 
        profiles = db.allProfiles(database=database)
        if profiles != False:
            mng.profiles = profiles
            mng.db = database
            print("Bot succesfully launched")
            while True:
                try:
                    bot.infinity_polling()
                except Exception as e:
                    print(e)
                    time.sleep(3)
        else:
            print("Couldn't parse profiles from DB")
    else:
        print("Couldn't connect to DB")

if __name__ == '__main__':
    main()