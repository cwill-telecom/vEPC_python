"""
MySQL client implementation

"""

import mysql.connector
import threading

class ConnInfo:
    """MySQL connection information"""
    
    def __init__(self):
        self.server = "localhost"
        self.user = "root"
        self.passwd = "mysql"
        self.db = "hss"

class MySql:
    """MySQL client class"""
    
    def __init__(self):
        self.conn_fd = None
        self.conn_info = ConnInfo()
    
    def conn(self):
        """Connect to MySQL server"""
        try:
            self.conn_fd = mysql.connector.connect(
                host=self.conn_info.server,
                user=self.conn_info.user,
                password=self.conn_info.passwd,
                database=self.conn_info.db
            )
            print("MySQL connection established")
        except mysql.connector.Error as err:
            print(f"MySQL connection error: {err}")
            raise
    
    def handle_query(self, query: str, result: list):
        """Execute SQL query and store results"""
        cursor = self.conn_fd.cursor()
        try:
            cursor.execute(query)
            rows = cursor.fetchall()
            result.append(rows)
            self.conn_fd.commit()
        except mysql.connector.Error as err:
            print(f"MySQL query error: {err}")
            raise
        finally:
            cursor.close()