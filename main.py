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
from loguru import logger

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
        bot.register_next_step_handler(message=message, callback=getNewProfileUsername, profile_name=message.text)
    else:
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
def getNewProfileUsername(message: types.Message, **kwargs):
    '''
    Getting new profile's username from User

    Args:
        message (types.Message): User's message
        profile_name (str): Name of the profile

    Check out register_next_step_handler from telebot documentation
    '''
    profile_name = kwargs['profile_name']
    if message.text != '.q':
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        bot.send_message(message.chat.id, text="_Please send new profile's _*password* _or_ *.q* _to quit or_ *.g* _to generate random._")
        bot.register_next_step_handler(message=message, callback=getNewProfilePassword, profile_name = profile_name, profile_username = message.text)
    else:
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
def getNewProfilePassword(message: types.Message, **kwargs):
    '''
    Getting or generating new profile's password from User

    Args:
        message (types.Message): User's message
        profile_name (str): Name of the new profile
        profile_username (str): Username of the new profile

    Check out register_next_step_handler from telebot documentation
    '''
    profile_name = kwargs['profile_name']
    profile_username = kwargs['profile_username']
    if message.text == '.q':
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
        return
    elif message.text == '.g':
        profile_password = generatePassword()
    else:
        profile_password = message.text
    bot.delete_message(message.chat.id, message.message_id)
    bot.delete_message(message.chat.id, message.message_id - 1)
    if mng.addProfile(profile_name, profile_username, profile_password):
        logger.info(f'Profile {profile_name} succesfully added to Manager.')
        bot.send_message(message.chat.id, text=f'_Succesfully created new profile:_ *{profile_name}*')
    else:
        logger.error(f"Profile {profile_name} wasn't added to Manager.")
        bot.send_message(message.chat.id, text=f'_Failed creating new profile:_ *{profile_name}*')

def generatePassword(length: int = 16) -> str:
    '''
    Generating random password

    Args:
        length (int): Length of the password

    Returns:
        password (str): Randomly generated password
    '''
    punctuation = '~-&@#_!?~@!_'
    if length < 6:
        length = 12
    uppercase_loc = secrets.choice(string.digits)  # random location of lowercase
    symbol_loc = secrets.choice(string.digits)  # random location of symbols
    lowercase_loc = secrets.choice(string.digits)  # random location of uppercase
    password = ""
    pool = string.ascii_letters + punctuation  # the selection of characters used
    for i in range(length):
        if i == uppercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_uppercase)
        elif i == lowercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_lowercase)
        elif i == symbol_loc:  # this is to ensure there is at least one symbol
            password += secrets.choice(punctuation)
        else:  # adds a random character from pool
            password += secrets.choice(pool)
    return password
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
            logger.info("Entered password succefully verified.")
            bot.send_message(message.chat.id, text='_Succesfully verified_ *master password.*')
            mng.hashedMasterPswd = mng.hashPassword(pswd, b'')
            mng.last_usage = datetime.datetime.now()
        else:
            logger.info("Entered password is not verified.")
            bot.send_message(message.chat.id, text='*Master password* _is not verified. Try one more time._')

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
        logger.info(f'Creds of {message.text} profile were sent to the user.')
        bot.send_message(message.chat.id, text=msg)
        threading.Thread(target=deleteMessage, args=(message.chat.id, message.message_id + 1, config.CREDS_DELETE_TIMEOUT,)).start()
    else:
        bot.send_message(message.chat.id, text=f'_Cannot find service with name_ *{message.text}*. _Try again_')
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

def getEditProfile(message: types.Message):
    '''
    Getting message with profile name to edit

    Args:
        message (types.Message): User's message
    '''
    if message.text in list(mng.profiles.keys()):
        bot.send_message(message.chat.id, text="_Send profile's username and password in the following format:\n_   *name|username|password*\n\n_If you want to generate password type .g after |. Use .q to quit._")
        bot.register_next_step_handler(message=message, callback=getEditProfileCreds, old_profile = message.text)
    else:
        bot.send_message(message.chat.id, text=f"_No such profile with name_ *{message.text}*. _Try again_")
def getEditProfileCreds(message: types.Message, **kwargs):
    '''
    Getting edit profile's updated credentials

    Args:
        message (types.Message): User's message
        old_profile (str): Name of the profile to be updated
    '''
    old_profile = kwargs['old_profile']
    if message.text == '.q':
        bot.send_message(message.chat.id, text='_Profile updating cancelled._')
    elif message.text.count('|') == 2:
        new_name, new_usr, new_pswd = message.text.split('|')
        if new_pswd == '.g':
            new_pswd = generatePassword()
        if mng.updateProfile(old_profile, new_name, new_usr, new_pswd):
            logger.info(f'Succefully changed profile {old_profile} to {new_name}. Creds updated.')
            bot.send_message(message.chat.id, text=f'_Succesfully updated profile_ *{new_name}({old_profile})*.')
            bot.delete_message(message.chat.id, message.message_id - 1)
            bot.delete_message(message.chat.id, message.message_id)
        else:
            logger.error(f"Couldn't update profile {old_profile}")
            bot.send_message(message.chat.id, text=f"_Failed to update profile_ *{old_profile}*")
    else:
        bot.send_message(message.chat.id, text='_Wrong format of the message.\nValid format:_ *profile|username|password*. _Try one more time_')

def getDeleteProfile(message: types.Message):
    '''
    Deleting Users's profile

    Args:
        message (types.Message): Users's message
    '''
    if message.text.count(' ') == 1:
        phrase, profile = message.text.split(' ')
        if phrase == 'DELETE' and (profile in list(mng.profiles.keys())):
            if mng.deleteProfile(profile):
                logger.info(f"Succefully deleted profile {profile}.")
                bot.send_message(message.chat.id, text=f'_Succesfully deleted profile_ *{profile}*')
            else:
                logger.error(f"Couldn't delete profile {profile}.")
                bot.send_message(message.chat.id ,text=f'_Failed to delete profile_ *{profile}*')

        elif phrase != "DELETE":
            bot.send_message(message.chat.id, text='_Wrong format of confirmation message. Try again_')
        else:
            bot.send_message(message.chat.id, text=f'_No profile with such name_ *{profile}*')
    else:
        bot.send_message(message.chat.id, text='_Wrong format of confirmation message. Try again_')

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
        logger.info(f'Unknown user. Username: {message.chat.username}. ID: {message.chat.id}')
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
        logger.info(f'Unknown user. Username: @{message.chat.username}. ID: {message.chat.id}.')
    else:
        if mng.isPswdValid():
            if message.text == 'Add Profile 🖊️':
                bot.send_message(message.chat.id, text="_Please send new profile's _*service name* _or_ *.q* _to quit_")
                bot.register_next_step_handler(message=message, callback=getNewProfileName)
            if message.text == 'Get Profile 🔑':
                msg = '*Your profiles:\n*'
                for serv in list(mng.profiles.keys()):
                    msg += f" - _{serv}_\n"
                msg += '\n_Send service name in the following message..._'
                bot.send_message(message.chat.id, msg)
                bot.register_next_step_handler(message, getProfileCreds)
            if message.text == 'Export Profiles 📤':
                filename = f'data-{datetime.datetime.now().strftime("%d-%m-%y")}.zip'
                file = ZipFile(filename, 'w')
                file.write(config.DB_NAME)
                file.write(config.VERIFIER_FILE)
                file.write(f'logs\\main_{datetime.datetime.now().strftime("%d-%m-%Y")}.log')
                file.close()
                bot.send_document(message.chat.id, data=open(filename, 'rb'))     
                logger.info("Sent file with logs, DB and verifier to the user.")
            if message.text == 'Edit Profile ⚙️':
                msg = '*Your profiles:\n*'
                for serv in list(mng.profiles.keys()):
                    msg += f" - _{serv}_\n"
                msg += '\n_Send service name in the following message..._'
                bot.send_message(message.chat.id, text=msg)
                bot.register_next_step_handler(message, getEditProfile)
            if message.text == 'Delete Profile 🗑️':
                bot.send_message(message.chat.id, text="_To delete profile follow instructions:_\n\n  _Type 'DELETE profile', where profile is name of the service you would like to delete_.\n\n _Make sure you have exported profiles before deletion in a safety reasons._")
                bot.register_next_step_handler(message, getDeleteProfile)
        else:
            logger.info('Master password is not verified.')
            verifyPassword(message)

def main():
    database = db.setUp()
    if database: 
        logger.info('Succesfully launched DB.')
        profiles = db.allProfiles(database=database)
        if profiles != False:
            logger.info('Succesfully got profiles from DB.')
            mng.profiles = profiles
            mng.db = database
            logger.info('Start polling TG server.')
            while True:
                try:
                    bot.infinity_polling()
                except Exception as e:
                    logger.error(f'TG polling error. Relaunch in 3 seconds. Error: {e}')
                    time.sleep(3)
        else:
            logger.critical("Couldn't parse DB profiles.")
    else:
        logger.critical("Couldn't launch DB.")

if __name__ == '__main__':
    if not os.path.exists('logs'):
        try:
            os.mkdir('logs')
        except PermissionError:
            print('Launch bot as administrator')
            input('Press ENTER to exit')
            exit()
    logger.add('logs\\main_{time:DD-MM-YYYY}.log', format="{time:DD.MM.YYYY - HH:mm:ss} | {level} | {message}", level='INFO', rotation='00:00', compression='zip', backtrace=True)
    logger.info('========= bot launched =========')
    main()