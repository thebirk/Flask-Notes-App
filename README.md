# Basic Flask, Flask-Session and Flask-SQLAlchemy app

## To run

1. Create a new virtualenv
    
    `$ virtualenv ./env`

2. Activate virtualenv
    
    Windows: `$ ./env/Scripts/activate.bat`
    
    *NIX: `$ source ./env/Scripts/activate`

3. Install required packages

    `$ pip install -r requirements.txt`

4. Setup database
    
    `$ python`

    `>>> import app`
    
    `>>> app.db.create_all()`

5. Start

    `python app.py`
