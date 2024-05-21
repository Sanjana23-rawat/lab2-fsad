const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dotenv = require("dotenv");
const app = express();

dotenv.config();

const PORT = 3000;
const secretKey = process.env.JWT_SECRET;

app.use(bodyParser.json());

const users = [];

// Register route
app.post('/register', async (req, res) => {
  const { username,email, password, role } = req.body;
  if (users.find(user => user.username === username)) {
    return res.status(400).json({ message: 'Username already exists' });
  }
  
  const encryptedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 999, username, email, password: encryptedPassword, role };
  users.push(newUser);

  res.status(201).json({ message: 'User registered successfully' });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id, role: user.role }, secretKey, { expiresIn: '1d' });

  res.json({ token });
});


// authenticating JWT token
function authentication(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
}

// Admin route
app.get('/admin', authentication, authorizeRoles('admin'), (req, res) => {
  res.json({ message: 'Admin route accessed successfully' });
});

// User route
app.get('/user', authentication, (req, res) => {
  res.json({ message: 'User route accessed successfully' });
});

// Get a list of registered users
app.get('/users', (req, res) => {
  res.json(users);
})

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
