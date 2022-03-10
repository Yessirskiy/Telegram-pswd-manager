import config
from telebot import TeleBot, types
import database as db
from Manager import Manager
import time
import datetime
import secrets
import string

bot = TeleBot(token=config.BOT_TOKEN, parse_mode='Markdown') # Initializing Telegram Bot
mng = Manager()

def getNewProfileName(message):
    if message.text != '.q':
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        bot.send_message(message.chat.id, text=f'_Name of the new service:_ *{message.text}*')
        mng.profiles.append({message.text : ()})
        bot.send_message(message.chat.id, text="_Please send new profile's _*username* _or_ *.q* _to quit_")
        bot.register_next_step_handler(message=message, callback=getNewProfileUsername)
    else:
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')

def getNewProfileUsername(message):
    if message.text != '.q':
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        service_name = list(mng.profiles[-1].keys())[0]
        hashed_username = mng.encryptData(message.text, pswd_hash=mng.hashedMasterPswd)
        mng.profiles[-1][service_name] += (hashed_username,)
        bot.send_message(message.chat.id, text='_Succesfully hashed new_ *username*.')
        bot.send_message(message.chat.id, text="_Please send new profile's _*password* _or_ *.q* _to quit or_ *.g* _to generate random._")
        bot.register_next_step_handler(message=message, callback=getNewProfilePassword)
    else:
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
        del mng.profiles[-1]
    
def getNewProfilePassword(message):
    if message.text == '.q':
        bot.send_message(message.chat.id, text='_Cancelled writing new profile._')
        del mng.profiles[-1]
        return
    elif message.text == '.g':
        generated_pswd = generatePassword()
        hashed_password = mng.encryptData(generated_pswd, pswd_hash=mng.hashedMasterPswd)
    else:
        hashed_password = mng.encryptData(message.text, pswd_hash=mng.hashedMasterPswd)
    bot.delete_message(message.chat.id, message.message_id)
    bot.delete_message(message.chat.id, message.message_id - 1)
    service_name = list(mng.profiles[-1].keys())[0]
    hashed_username = mng.profiles[-1][service_name][0]
    mng.profiles[-1][service_name] += (hashed_password,)
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
        del mng.profiles[-1]
        bot.send_message(message.chat.id, text=f'_Failed creating new profile:_ *{service_name}*')

def generatePassword(length: int = 12) -> str:
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

def getMasterPassword(message):
    if message.text != '.q':
        pswd = message.text
        bot.delete_message(message.chat.id, message.message_id)
        bot.delete_message(message.chat.id, message.message_id - 1)
        mng.hashedMasterPswd = mng.hashMasterPassword(pswd)
        mng.last_usage = datetime.datetime.now()
        bot.send_message(message.chat.id, text='_Succesfully updated_ *master password.*')

@bot.message_handler(commands=['start'])
def greetings(message):
    if message.chat.id not in config.ADMIN_IDS: # Auth on Telegram Level
        bot.send_message(message.chat.id, text="_Unfortunately you don't have access to this bot 🙅_")
    else:
        main_menu_markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
        add_profile_btn = types.KeyboardButton(text = 'Add Profile 🖊️')
        edit_profile_btn = types.KeyboardButton(text = 'Edit Profile ⚙️')
        delete_profile_btn = types.KeyboardButton(text = 'Delete Profile 🗑️')
        export_profiles_btn = types.KeyboardButton(text = 'Export Profiles 📤')
        manage_master_btn = types.KeyboardButton(text= 'Manage Master Account 🔑')
        main_menu_markup.add(add_profile_btn, edit_profile_btn, delete_profile_btn, export_profiles_btn, manage_master_btn)
        bot.send_message(message.chat.id, text='_Hello, use buttons from menu below to manage your passwords :)_', reply_markup=main_menu_markup)

@bot.message_handler(content_types=['text'])
def handle_menu(message):
    if message.chat.id not in config.ADMIN_IDS: # Auth on Telegram Level
        bot.send_message(message.chat.id, text="_Unfortunately you don't have access to this bot 🙅_")
    else:
        if message.text == 'Add Profile 🖊️':
            if mng.isPswdValid():
                bot.send_message(message.chat.id, text="_Master Password currently is valid_\n_Please send new profile's _*service name* _or_ *.q* _to quit_")
                bot.register_next_step_handler(message=message, callback=getNewProfileName)
            else:
                bot.send_message(message.chat.id, text="_Master Password currently is expired or not provided._\n\n_Send_ *master password* _in the next message or_ *.q* _to quit._")
                bot.register_next_step_handler(message, callback=getMasterPassword)


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