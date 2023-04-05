## SimpleWebApp

this project has auth and user page and also
a public page where users can chat with each other.

app uses postgres and a simple table named: users.

to run this project you need to first define users table
with following columns: username, fullname, email and hashed_password.

then run the following command:
```bash
pip install -r requirements.txt
```

then you need to start the server:
```bash
uvicorn main:app --reload
```