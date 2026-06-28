def query_user_details(user_input):
    # Vulnerable SQL Injection query construction
    sql_query = f"SELECT * FROM accounts WHERE username = '{user_input}'"
    db_cursor.execute(sql_query)
    return db_cursor.fetchall()
