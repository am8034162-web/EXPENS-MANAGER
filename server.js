const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public'))); // Serves your frontend files

// Initialize SQLite Database
const dbFile = path.join(__dirname, 'vault.db');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
    }
});

// Create Tables for Users, Transactions, and Notes
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        username TEXT UNIQUE,
        password TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        desc TEXT,
        amount REAL,
        category TEXT,
        type TEXT,
        date TEXT,
        FOREIGN KEY(userId) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        title TEXT,
        content TEXT,
        date TEXT,
        FOREIGN KEY(userId) REFERENCES users(id)
    )`);
});

// --- API ROUTES ---

// 1. Register User
app.post('/api/register', async (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO users (email, username, password) VALUES (?, ?, ?)`;
        
        db.run(query, [email, username, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Username or Email already exists.' });
            }
            res.json({ success: true, userId: this.lastID, username, email });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// 2. Login User
app.post('/api/login', (req, res) => {
    const { query: loginQuery, password } = req.body; // loginQuery can be username or email

    const sql = `SELECT * FROM users WHERE username = ? OR email = ?`;
    db.get(sql, [loginQuery, loginQuery], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Invalid username/email or password.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: 'Invalid username/email or password.' });
        }

        // Fetch user's transactions and notes
        db.all(`SELECT * FROM transactions WHERE userId = ? ORDER BY id DESC`, [user.id], (err, transactions) => {
            db.all(`SELECT * FROM notes WHERE userId = ? ORDER BY id DESC`, [user.id], (err, notes) => {
                res.json({
                    success: true,
                    user: { id: user.id, username: user.username, email: user.email },
                    transactions: transactions || [],
                    notes: notes || []
                });
            });
        });
    });
});

// 3. Add Transaction
app.post('/api/transactions', (req, res) => {
    const { userId, desc, amount, category, type, date } = req.body;
    const sql = `INSERT INTO transactions (userId, desc, amount, category, type, date) VALUES (?, ?, ?, ?, ?, ?)`;
    
    db.run(sql, [userId, desc, amount, category, type, date], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to add transaction' });
        res.json({ success: true, id: this.lastID });
    });
});

// 4. Delete Transaction
app.delete('/api/transactions/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM transactions WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete transaction' });
        res.json({ success: true });
    });
});

// 5. Add Note
app.post('/api/notes', (req, res) => {
    const { userId, title, content, date } = req.body;
    const sql = `INSERT INTO notes (userId, title, content, date) VALUES (?, ?, ?, ?)`;
    
    db.run(sql, [userId, title, content, date], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to add note' });
        res.json({ success: true, id: this.lastID });
    });
});

// 6. Delete Note
app.delete('/api/notes/:id', (req, res) => {
    const { id } = req.params;
    db.run(`DELETE FROM notes WHERE id = ?`, [id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete note' });
        res.json({ success: true });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});