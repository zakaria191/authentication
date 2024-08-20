const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const csurf = require('csurf');
const app = express();
const port = 4040;

app.set('view engine', 'ejs');

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));

// Create and use the csurf middleware
const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

// Store registered users in an array
const registeredUsers = [];

// Registration form
app.get('/', (req, res) => {
  res.render('register', { csrfToken: req.csrfToken() });
});

// Registration route
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Check if the username is already taken
  if (registeredUsers.some(user => user.username === username)) {
    return res.status(400).send('Username already taken.');
  }

  // Hash the password
  const hashedPassword = bcrypt.hashSync(password, 10);

  // Store the user's credentials in the array
  registeredUsers.push({
    username,
    password: hashedPassword
  });

  // Render the registration success view
  res.render('protected');
});

// Login form
app.get('/login', (req, res) => {
  res.render('login', { csrfToken: req.csrfToken() });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Find the user by username in the array
  const user = registeredUsers.find(user => user.username === username);

  if (!user) {
    return res.status(401).send('You are not registered.');
  }

  // Compare the hashed password with the entered password
  const passwordMatch = bcrypt.compareSync(password, user.password);

  if (!passwordMatch) {
    return res.status(401).send('Invalid password.');
  }

  // Create a session for the user
  req.session.isAuthenticated = true;

  // Render the login success view
  res.render('login_success');
});

// Protected route
app.get('/protected', (req, res) => {
  if (!req.session.isAuthenticated) {
    return res.status(401).send('Unauthorized. Please log in.');
  }

  // Render the protected route view
  res.render('protected');
});

// Route to display user information
app.get('/users', (req, res) => {
  if (!req.session.isAuthenticated) {
    return res.status(401).send('Unauthorized. Please log in.');
  }

  // Return the list of registered users
  res.json(registeredUsers);
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out.');
    }
    
    res.clearCookie('connect.sid');
    res.send('login');
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
