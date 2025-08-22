const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const uuid = require('uuid');
const cookieParser = require('cookie-parser');

const app = express();
const DB_FILE = path.join(__dirname, 'mapdata.json');
const SESSIONS = new Map();

// Initialize database with automatic creation
function initializeDatabase() {
  try {
    // Create directory if needed
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Create file if not exists
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], annotations: [] }));
      console.log('Created new database file');
    }

    // Verify database structure
    const rawData = fs.readFileSync(DB_FILE, 'utf8');
    let db = JSON.parse(rawData);
    
    // Ensure required collections exist
    if (!db.users) db.users = [];
    if (!db.annotations) db.annotations = [];
    
    // Create default admin if missing
    if (!db.users.some(u => u.username === 'admin')) {
      const hashedPass = bcrypt.hashSync('admin', 10);
      db.users.push({ 
        id: uuid.v4(), 
        username: 'admin',
        password: hashedPass,
        createdAt: new Date().toISOString()
      });
      fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    }
    
    return db;
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
}

// Load or create database
let db = initializeDatabase();

app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

// Auth middleware
const auth = (req, res, next) => {
  const sessionId = req.cookies.sessionId;
  if (!sessionId || !SESSIONS.has(sessionId)) return res.status(401).send('Unauthorized');
  req.user = SESSIONS.get(sessionId);
  next();
};

// Routes
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find(u => u.username === username);
  
  if (user && bcrypt.compareSync(password, user.password)) {
    const sessionId = uuid.v4();
    SESSIONS.set(sessionId, { id: user.id, username });
    res.cookie('sessionId', sessionId, { 
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/logout', (req, res) => {
  const sessionId = req.cookies.sessionId;
  SESSIONS.delete(sessionId);
  res.clearCookie('sessionId');
  res.sendStatus(200);
});

app.get('/api/annotations', auth, (req, res) => {
  res.json(db.annotations.filter(a => a.userId === req.user.id));
});

app.post('/api/annotations', auth, (req, res) => {
  try {
    const { text, x, y } = req.body;
    
    if (!text || typeof x !== 'number' || typeof y !== 'number') {
      return res.status(400).json({ error: 'Invalid annotation data' });
    }

    const annotation = {
      id: uuid.v4(),
      text: text.substring(0, 255),
      x,
      y,
      userId: req.user.id,
      createdAt: new Date().toISOString()
    };
    
    db.annotations.push(annotation);
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    res.json(annotation);
  } catch (error) {
    console.error('Error saving annotation:', error);
    res.status(500).json({ error: 'Failed to save annotation' });
  }
});

app.delete('/api/annotations/:id', auth, (req, res) => {
  try {
    const initialLength = db.annotations.length;
    db.annotations = db.annotations.filter(a => a.id !== req.params.id);
    
    if (db.annotations.length === initialLength) {
      return res.status(404).json({ error: 'Annotation not found' });
    }
    
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    res.sendStatus(204);
  } catch (error) {
    console.error('Error deleting annotation:', error);
    res.status(500).json({ error: 'Failed to delete annotation' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
  console.log('Database file:', DB_FILE);
});