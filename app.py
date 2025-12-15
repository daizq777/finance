import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET","POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    # TODO:
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        cur_price = lookup(symbol=symbol)["price"]
        if request.form.get("operation") == "sell":
            if int(request.form.get("cur_share")) < shares:
                return apology("Shares should not be more than what you have.")
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",cur_price*shares,session["user_id"])
            db.execute("UPDATE holdings SET shares = shares - ? WHERE user_id = ? AND symbol = ?",shares,session["user_id"],symbol)
            # insert into purchases
            db.execute("INSERT INTO transactions (user_id,symbol,price,shares,sum,action) VALUES (?,?,?,?,?,?)",session["user_id"],symbol,cur_price,shares,cur_price*shares,"sell")
        if request.form.get("operation") == "buy":
            if not shares or shares < 0:
                return apology("Shares should be a positive integer.")
            db.execute("UPDATE users SET cash = cash - ? WHERE id = ?",cur_price*shares,session["user_id"])
            # insert into purchases
            db.execute("UPDATE holdings SET shares = shares + ? WHERE user_id = ? AND symbol = ?",shares,session["user_id"],symbol)
            db.execute("INSERT INTO transactions (user_id,symbol,price,shares,sum) VALUES (?,?,?,?,?)",session["user_id"],symbol,cur_price,shares,cur_price*shares)
    purchases = db.execute("SELECT symbol,shares FROM holdings WHERE user_id = ?",session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?",session["user_id"])[0]["cash"]
    balance = cash
    prices={}
    for line in purchases:
        prices[line["symbol"]] = lookup(symbol=line["symbol"])["price"]
        balance += prices[line["symbol"]]*line["shares"]
        
    return render_template("index.html",purchases=purchases,balance=balance,cash=cash,prices=prices)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    symbols = db.execute("SELECT symbol FROM holdings WHERE user_id = ?",session["user_id"])
    ownedsymbols = [s["symbol"] for s in symbols]
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("Please fill in the symbol.")
        if not shares or shares <= 0:
            return apology("Please fill in the shares with positive integer.")
        price = lookup(symbol=symbol)["price"]
        sum = price * shares
        user_balance = db.execute("SELECT cash FROM users WHERE id=?",session["user_id"])[0]["cash"]
        if user_balance < sum:
            return apology("You don't have sufficient balance.")
        # update users balance
        db.execute("UPDATE users SET cash = ? WHERE id = ?",user_balance-sum,session["user_id"])
        # insert into purchases
        db.execute("INSERT INTO transactions (user_id,symbol,price,shares,sum) VALUES (?,?,?,?,?)",session["user_id"],symbol,price,shares,sum)
        if symbol not in ownedsymbols:
            db.execute("INSERT INTO holdings (user_id,shares,symbol) VALUES (?,?,?)",session["user_id"],shares,symbol)
        else:
            db.execute("UPDATE holdings SET user_id=?, shares=shares+? WHERE symbol=? ",session["user_id"],shares,symbol)
        return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    data = db.execute("SELECT symbol,shares,time,action FROM transactions WHERE user_id = ?",session["user_id"])
    return render_template("history.html",data=data)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Please fill in stock symbol.")
        res = lookup(symbol=symbol)
        if not res:
            return apology("Invalid symbol.")
        return render_template("quoted.html",res=res)
    return render_template("quote.html")


@app.route("/register", methods=["GET","POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username=request.form.get("username")
        password=request.form.get("password")
        confirmation=request.form.get("confirmation")
        if not username:
            return apology("Please fill in your username.")
        if not password:
            return apology("Please fill in your password.")
        if password != confirmation:
            return apology("Confirmation wrong.")
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)",username,generate_password_hash(password))
            return redirect("/login")
        except ValueError:
            return apology("Username already exists.")
    return render_template("register.html")
    


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    own = db.execute("SELECT symbol,shares FROM holdings WHERE user_id = ?",session["user_id"])
    if request.method == "POST":
        symbol = request.form.get("symbol")
        sys = {}
        for s in own:
            own_symbol = s["symbol"]
            own_shares = s["shares"]
            sys[own_symbol] = own_shares
        if symbol not in sys:
            return apology("You do not own this stock.")
        shares = int(request.form.get("shares"))
        if shares < 0 or shares > sys[symbol]:
            return apology("Should be a positive number no greater than what you own.")
        price = lookup(symbol=symbol)["price"]
        # 把该股票从holdings中减少
        # 添加记录到transactions action=sell
        db.execute("UPDATE holdings SET user_id = ?, shares = shares - ? WHERE symbol = ?",session["user_id"],shares,symbol)
        db.execute("DELETE FROM holdings WHERE user_id = ? AND symbol = ? AND shares <= 0", session["user_id"], symbol)
        db.execute("INSERT INTO transactions (user_id,symbol,price,shares,sum,action) VALUES(?,?,?,?,?,?)",session["user_id"],symbol,price,shares,price*shares,"sell")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",price*shares,session["user_id"])
        return redirect("/")
    return render_template("sell.html",symbols=own)
    
@app.route("/change_password",methods=["GET","POST"])
@login_required
def change_password():
    '''Change their passwords And add addtional cash to their account'''
    username = db.execute("SELECT username FROM users WHERE id=?",session["user_id"])[0]["username"]
    if request.method == "POST":
        password = request.form.get("password")
        if not password:
            return apology("Please fill your new password to change.")
        db.execute("UPDATE users SET hash = ? WHERE id = ?",generate_password_hash(password),session["user_id"])
        return redirect("/")
    return render_template("change_password.html",username=username)


@app.route("/add_cash",methods=["GET","POST"])
@login_required
def add_cash():
    username = db.execute("SELECT username FROM users WHERE id=?",session["user_id"])[0]["username"]
    if request.method == "POST":
        amount = int(request.form.get("cash"))
        if not amount or amount <= 0:
            return apology("Please add positive integer to your account.")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",amount,session["user_id"])
        db.execute("INSERT INTO usercash (cash_amount,user_id) VALUES (?,?)",amount,session["user_id"])
        return redirect("/")
    return render_template("add_cash.html",username=username)