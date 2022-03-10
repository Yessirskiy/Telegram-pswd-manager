import config
from telebot import TeleBot, types
import database as db
from Manager import Manager
import time

bot = TeleBot(token=config.BOT_TOKEN, parse_mode='Markdown') # Initializing Telegram Bot
mng = Manager()

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
    pass
 
def main():
    database = db.setUp()
    if database: 
        profiles = db.allProfiles(database=database)
        if profiles != False:
            mng.profiles = profiles
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