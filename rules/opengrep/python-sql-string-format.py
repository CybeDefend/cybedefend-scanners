# Annotated test file for python-sql-string-format. Deliberately vulnerable: do not run.


def by_name(cursor, name):
    # ruleid: python-sql-string-format
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)


def by_id(cursor, user_id):
    # ruleid: python-sql-string-format
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def by_email(conn, email):
    # ruleid: python-sql-string-format
    conn.execute("SELECT * FROM users WHERE email = '{}'".format(email))


def by_role(cursor, role):
    # ruleid: python-sql-string-format
    cursor.execute("SELECT * FROM users WHERE role = '" + role + "'")


def by_name_bound(cursor, name):
    # ok: python-sql-string-format
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


def count(cursor):
    # ok: python-sql-string-format
    cursor.execute("SELECT count(*) FROM users")
