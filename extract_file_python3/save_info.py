import sqlite3 as sql
from sqlite3 import Error

def create_connection(db_file):
    """ create a database connection to a SQLite database """
    try:
        conn = sql.connect(db_file)
        return conn
    except Error as e:
        print(e)
    return None

def create_table(conn, create_table_sql_schema):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql_schema: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql_schema)
    except Error as e:
        print(e)

def insert_data(conn, insert_schema , data):
    """
    Create a new project into the projects table
    :param conn: Connection object
    :param insert_schema: 
        ex: ''' INSERT INTO example(name,begin_date,end_date) VALUES(?,?,?) '''
    :param data: match the colums of table
    :return: id
    """
    cur = conn.cursor()
    cur.execute(insert_schema, data)
    if cur.lastrowid is not None:
        return cur.lastrowid
    return None

if __name__ == '__main__':
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS projects (
                                        id integer PRIMARY KEY,
                                        name text NOT NULL,
                                        begin_date text,
                                        end_date text
                                    ); """

    conn=create_connection("pythonsqlite.db")
    with conn:
        create_table(conn,sql_create_projects_table)
        project = (123456,'Cool App with SQLite & Python', '2015-01-01', '2015-01-30')
        print(insert_data(conn,'INSERT INTO projects(id,name,begin_date,end_date) VALUES (?,?,?,?)',project))
