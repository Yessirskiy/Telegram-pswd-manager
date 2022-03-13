from typing import Tuple, Dict, List
import config
import sqlite3


def allProfiles(database: Tuple[sqlite3.Connection, sqlite3.Cursor]) -> Dict:
    '''
    Returns all the profiles from DB

    Args:
        database (tuple[sqlite3.Connection, sqlite3.Cursor]): connection and cursor of DB
    
    Returns:
        profiles (List[Dict]) | Literal[False]: List of dictionaries with profiles 
            {service_name : (username_hash, password_hash)}
    '''
    
    try:
        profiles = {}
        con, cur = database
        fetching_query = '''SELECT * FROM profiles'''
        cur.execute(fetching_query)
        data = cur.fetchall()
        for profile in data:
            profile_id, service, username_hash, password_hash = profile
            profiles[service] = (username_hash.encode(), password_hash.encode())
        return profiles
    except sqlite3.Error as e:
        print(e)
        return False
    
def newProfile(service_name: str, username_hash: str, password_hash: str, database: Tuple[sqlite3.Connection, sqlite3.Cursor]) -> bool:
    '''
    Creates new profile in DB

    Args:
        service_name (str): Name of the profile's service
        username_hash (str): Hashed username of the profile's service
        password_hash (str): Hashed password of the profile's service
        database (tuple[sqlite3.Connection, sqlite3.Cursor]): connection and cursor of DB
    
    Returns:
        result (bool): Success of operation
    '''
    try:
        con, cur = database
        insert_query = '''INSERT INTO profiles(service, username, password) VALUES(?, ?, ?)'''
        cur.execute(insert_query, (service_name, username_hash, password_hash,))
        con.commit()
    except sqlite3.Error as e:
        print(e)
        return False
    return True

def updateProfile(service_name: str, new_name: str, username_hash: str, password_hash: str, database: Tuple[sqlite3.Connection, sqlite3.Cursor]) -> bool:
    '''
    Updating username and password hashes in DB by service_name

    Args:
        service_name (str): Name of the service to update
        new_name (str): New name of the profile
        username_hash (str): Hash of new username
        password_hash (str): Hash of new password
        database (Tuple[sqlite3.Connection, sqlite3.Cursor]): database (tuple[sqlite3.Connection, sqlite3.Cursor]): connection and cursor of DB
    
    Returns:
        result (bool): True - success, False - fail
    '''
    con, cur = database
    query = f'UPDATE profiles SET username = ?, password = ?, service = ? WHERE service = ?'
    try:
        cur.execute(query, (username_hash, password_hash, new_name, service_name,))
        con.commit()
    except sqlite3.Error as e:
        print(e)
        return False
    return True
    
def deleteProfile(service_name: str, database: Tuple[sqlite3.Connection, sqlite3.Cursor]) -> bool:
    '''
    Deleting profile in DB table

    Args:
        service_name (str): Name of the service to update
        database (Tuple[sqlite3.Connection, sqlite3.Cursor]): database (tuple[sqlite3.Connection, sqlite3.Cursor]): connection and cursor of DB

    Returns:
        result (bool): True - success, False - fail
    '''
    con, cur = database
    query = 'DELETE FROM profiles WHERE service = ?'
    try:
        cur.execute(query, (service_name,))
        con.commit()
    except sqlite3.Error as e:
        print(e)
        return False
    return True

def setUp():
    '''     
    Setup database

    Returns:
        tuple[Connection, Cursor] | Literal[False]
            con (sqlite3.Connection): Connection to database
            cur (sqlite3.Cursor): Cursor of current connection
    '''
    try:
        con = sqlite3.connect(database=config.DB_NAME, check_same_thread=False)
        cur = con.cursor()
        init_query = '''CREATE TABLE IF NOT EXISTS profiles (
            id integer PRIMARY KEY,
            service text NOT NULL,
            username text,
            password text
        );'''
        cur.execute(init_query)
    except sqlite3.Error as e:
        print(e)
        return False
    return con, cur
    

