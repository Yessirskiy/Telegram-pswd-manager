from typing import Tuple, Dict, List
import config
import sqlite3


def allProfiles(database: Tuple[sqlite3.Connection, sqlite3.Cursor]):
    '''
    Returns all the profiles from DB

    Args:
        database (tuple[sqlite3.Connection, sqlite3.Cursor]): connection and cursor of DB
    
    Returns:
        profiles (List[Dict]) | Literal[False]: List of dictionaries with profiles 
            {service_name : (username_hash, password_hash)}
    '''
    
    try:
        profiles = []
        con, cur = database
        fetching_query = '''SELECT * FROM profiles'''
        cur.execute(fetching_query)
        data = cur.fetchall()
        for profile in data:
            profile_id, service, username_hash, password_hash = profile
            profiles.append({service : (username_hash, password_hash)})
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
    

