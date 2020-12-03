import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
#app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
#if not os.environ.get("API_KEY"):
    #raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    
    # Searches if user has bought stocks
    id_dicts = db.execute("SELECT user_id FROM shares")
    if not any(d['user_id'] == session["user_id"] for d in id_dicts):
        cash_list = db.execute("SELECT cash FROM users WHERE id=:usid", usid=session["user_id"])
        cash = float(cash_list[0]["cash"])
        return render_template("index_new.html", cash=str(round(cash,2)))
    
    # Create list with needed values
    values_dicts = db.execute("SELECT *  FROM shares WHERE user_id = :usid", usid=session["user_id"])
    values_list = [None] * len(values_dicts)
    net_worth_list = [None] * len(values_dicts)

    # Get table values
    for i in range(len(values_dicts)):
        symbol = lookup(values_dicts[i]["share"])["symbol"]
        name = lookup(symbol)["name"]
        price = lookup(symbol)["price"]
        shares_dict = db.execute("SELECT share_count FROM shares WHERE share = :share AND user_id = :usid", share=symbol, usid=session["user_id"])
        
        total_shares = int(shares_dict[0]["share_count"])
            
        total = float(price) * total_shares
        
        cash = db.execute("SELECT cash FROM users WHERE id=:usid", usid=session["user_id"])[0]["cash"]
        
        if i == 0:
            net_worth_list[i] = round(float(total + cash), 2)
        else:
            net_worth_list[i] = round(float(total + net_worth_list[i - 1]), 2)
            
        net_worth = net_worth_list[-1]
            
        values_list[i] = {'symbol':symbol, 'name':name, 'price':price, 'shares':total_shares, 'total':round(total,2), 'cash':round(cash,2)}
    
    return render_template("index.html", net_worth=net_worth, longitude=len(values_list), values_list=values_list)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
            
        # Creates dict
        symbol_info = lookup(request.form.get("symbol"))
        
        # Checks that symbol exists
        if symbol_info == None:
            return apology("Invalid Symbol", 403)
        
        # Ensure number of shares was submitted
        if not request.form.get("shares"):
            return apology("must provide number of shares", 403)
            
        # Ensure shares is valid
        try:
            if not int(request.form.get("shares")) > 0:
                return apology("invalid value", 403)
        except ValueError:
            return apology("invalid value", 403)
            
        # Ensure there's enough money to buy share
        user_money = db.execute("SELECT cash FROM users WHERE id=:userid", userid=session["user_id"])
        cash = float(user_money[0]["cash"])
        if cash < float(symbol_info["price"]) * float(request.form.get("shares")):
            return apology("Not enough money", 403)
            
        # Update user
        updated_money = cash - (float(symbol_info["price"]) * float(request.form.get("shares")))
        db.execute("UPDATE users SET cash = :updated WHERE id=:usid", updated=updated_money, usid=session["user_id"])
        
        # Update shares table
        symbol_dicts = db.execute("SELECT share FROM shares WHERE user_id = :usid", usid=session["user_id"])
        exist = 0
        for i in range(len(symbol_dicts)):
               if symbol_dicts[i]["share"].upper() == request.form.get("symbol").upper():
                exist = 1
                break
        
        if exist == 0:
            db.execute("INSERT INTO shares (user_id, share, share_count) VALUES (:usid, :symbol, :count)", usid=session["user_id"], symbol=request.form.get("symbol").upper(), count=int(request.form.get("shares")))
        else:
            db.execute("UPDATE shares SET share_count = share_count + :count WHERE share = :symbol AND user_id = :usid", count=int(request.form.get("shares")), symbol=request.form.get("symbol").upper(), usid=session["user_id"])
        
        # Record transaction
        db.execute("INSERT INTO history (user_id, symbol, shares, time, price) VALUES (:usid, :symbol, :shares, :time, :price)", usid=session["user_id"], symbol=symbol_info["symbol"], shares=request.form.get("shares"), time=str(db.execute("SELECT CURRENT_TIMESTAMP")[0]["CURRENT_TIMESTAMP"]), price=str(symbol_info["price"]))
        
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")
    

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    
    value_dicts = db.execute("SELECT * FROM history WHERE user_id = :usid", usid=session["user_id"])
    return render_template("history.html", value_dicts=value_dicts)
    


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)
        
        # Gets symbol
        symbol = request.form.get("symbol")
        
        # Creates dict
        symbol_info = lookup(symbol)
        
        # Checks that symbol exists
        if symbol_info == None:
            return apology("Invalid Symbol", 403)
        
        # Redirect user to home page
        return render_template("quoted.html", name=symbol_info["name"], sym=symbol_info["symbol"], price=symbol_info["price"])

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")
    


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
            
        # Ensure password confirmation was submitted
        elif not request.form.get("password_confirm"):
            return apology("must provide password confirmation", 403)
            
        # Ensure password and confirmation are the same
        elif request.form.get("password_confirm") != request.form.get("password"):
            return apology("Passwords are different", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        
        # Checks that username is available
        if len(rows) != 0:
            return apology("Username is not available", 403)

        # Hashes password
        hashed = generate_password_hash(request.form.get("password"))
        
        # Inserts account into table
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashed)", username=request.form.get("username"), hashed=hashed)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")
    

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Ensure data is inputted
        if not request.form.get("symbol"):
            return apology("Insert symbol", 403)
            
        if not request.form.get("shares"):
            return apology("Insert number of shares to sell", 403)
            
        # Ensure shares value is valid
        try:
            if not int(request.form.get("shares")) > 0:
                return apology("invalid value", 403)
        except ValueError:
            return apology("invalid value", 403)
        
        # Ensure there's enough shares to sell    
        share_count_dict = db.execute("SELECT share_count FROM shares WHERE user_id=:usid AND share=:share", usid=session["user_id"], share=request.form.get("symbol").upper())
        share_count = int(share_count_dict[0]["share_count"])
        
        if int(request.form.get("shares")) > share_count:
                return apology("You don't own enough shares", 403)
        
        # Create variables
        symbol = request.form.get("symbol").upper()
        quantity = int(request.form.get("shares"))
        
        # Add cash to user data
        new_cash = float(lookup(symbol)["price"]) * quantity
        db.execute("UPDATE users SET cash= cash + :cash WHERE id=:usid", cash=new_cash, usid=session["user_id"])   
                
        # Remove shares of user data
        db.execute("UPDATE shares SET share_count = share_count - :shares WHERE user_id=:usid AND share = :share", shares=quantity,share=symbol, usid=session["user_id"])
        db.execute("DELETE FROM shares WHERE user_id=:usid AND share_count = :shares", usid=session["user_id"], shares=0)
        
        # Record transaction
        db.execute("INSERT INTO history (user_id, symbol, shares, time, price) VALUES (:usid, :symbol, :shares, :time, :price)", usid=session["user_id"], symbol=symbol, shares='-' + str(quantity), time=str(db.execute("SELECT CURRENT_TIMESTAMP")[0]["CURRENT_TIMESTAMP"]), price=str(lookup(symbol)["price"]))
        
        return redirect("/")
            
    else:
        # Create list with purchased symbols
        symbol_dicts = db.execute("SELECT share FROM shares WHERE user_id=:usid", usid=session["user_id"])
        symbol_list = [None] * len(symbol_dicts)
        
        # Insert symbols into list
        for i in range(len(symbol_dicts)):
            symbol_list[i] = symbol_dicts[i]["share"]
        
        return render_template("sell.html", longitude=len(symbol_dicts), symbols=symbol_list)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure current password was submitted
        if not request.form.get("current_password"):
            return apology("must provide your password", 403)
            
        password = request.form.get("current_password")

        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return apology("must provide a newpassword", 403)
            
        new_password = request.form.get("new_password")
            
        # Ensure password input is correct
        rows = db.execute("SELECT * FROM users WHERE id = :usid", usid=session["user_id"])

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("incorrect password", 403)
            
        # Change password
        hashed = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash=:hashed WHERE id=:usid", hashed=hashed, usid=session["user_id"])
        
        # Close session
        session.clear()

        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_password.html")
    

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
