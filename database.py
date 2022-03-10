import config
import sqlite3

#def newProfile(service_name: str, )


def setUp():
    '''     
    Setup database

    Returns:
        tuple[Connection, Cursor] | Literal[False]
            con (sqlite3.Connection): Connection to database
            cur (sqlite3.Cursor): Cursor of current connection
    '''
    try:
        con = sqlite3.connect(database=config.DB_NAME)
        cur = con.cursor()
    except sqlite3.Error as e:
        print(e)
        return False
    return con, cur
    

