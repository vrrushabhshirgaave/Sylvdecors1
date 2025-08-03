const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors({ origin: 'https://your-username.github.io' })); // Replace with your GitHub Pages URL
app.use(express.json());

const pool = new Pool({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
    ssl: { rejectUnauthorized: false }
});

// Initialize database
async function initDb() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS enquiries (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255),
                email VARCHAR(255),
                phone VARCHAR(255),
                furniture_type VARCHAR(255),
                message TEXT,
                timestamp TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(255) PRIMARY KEY,
                password VARCHAR(255)
            );
        `);
        const ownerExists = await pool.query('SELECT * FROM users WHERE username = $1', ['owner']);
        if (!ownerExists.rows.length) {
            const hashedPassword = await bcrypt.hash('sylva123', 10);
            await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', ['owner', hashedPassword]);
        }
        console.log('Database initialized');
    } catch (error) {
        console.error('Database initialization failed:', error.message);
    }
}
initDb();

// Middleware to verify JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send('Access denied');
    try {
        jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (error) {
        res.status(403).send('Invalid token');
    }
}

// Submit enquiry
app.post('/api/enquiries', async (req, res) => {
    const { name, email, phone, furniture_type, message, timestamp } = req.body;
    try {
        await pool.query(
            'INSERT INTO enquiries (name, email, phone, furniture_type, message, timestamp) VALUES ($1, $2, $3, $4, $5, $6)',
            [name, email, phone, furniture_type, message, timestamp]
        );
        res.status(200).send('Enquiry submitted');
    } catch (error) {
        console.error('Error submitting enquiry:', error.message);
        res.status(500).send(error.message);
    }
});

// Owner login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT password FROM users WHERE username = $1', [username]);
        if (result.rows.length && await bcrypt.compare(password, result.rows[0].password)) {
            const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ token });
        } else {
            res.status(401).send('Invalid credentials');
        }
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).send(error.message);
    }
});

// Fetch enquiries
app.get('/api/enquiries', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM enquiries ORDER BY timestamp DESC');
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching enquiries:', error.message);
        res.status(500).send(error.message);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
