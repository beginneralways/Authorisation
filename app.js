// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Create express app
const app = express();

// Use json parser and cors middleware
app.use(express.json());
app.use(cors());

// Connect to mongodb database
mongoose.connect('mongodb://localhost:27017/role-based-auth',);

// Define user schema and model
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['admin', 'user'],
        default: 'user'
    }
});

const User = mongoose.model('User', UserSchema);

// Define a secret key for jwt
const secretKey = 'some-secret-key';

// Define a function to generate jwt token
const generateToken = (user) => {
    return jwt.sign({
        id: user._id,
        username: user.username,
        role: user.role
    }, secretKey, {
        expiresIn: '1h'
    });
};

// Define a function to verify jwt token
const verifyToken = (req, res, next) => {
    // Get the authorization header from the request
    const authHeader = req.headers.authorization;
    // const authHeader = req.headers["Authorization"]

    // Check if the header exists and has the format 'Bearer token'
    if (authHeader && authHeader.startsWith('Bearer ')) {
        // Extract the token from the header
        const token = authHeader.split(' ')[1];

        // Verify the token using the secret key
        jwt.verify(token, secretKey, (err, decoded) => {
            // If there is an error, return 401 unauthorized response
            if (err) {
                return res.status(401).json({
                    message: 'Invalid or JJ token'
                });
            }

            // If the token is valid, attach the decoded user to the request object
            req.user = decoded;

            // Call the next middleware function
            next();
        });
    } else {
        // If the header is missing or invalid, return 401 unauthorized response
        return res.status(401).json({
            message: 'Missing or malformed authorization header'
        });
    }
};

// Define a function to check the user role
const checkRole = (role) => {
    // Return a middleware function that checks the user role
    return (req, res, next) => {
        // Get the user from the request object
        const user = req.user;

        // Check if the user has the required role
        if (user && user.role === role) {
            // Call the next middleware function
            next();
        } else {
            // If the user does not have the required role, return 403 forbidden response
            return res.status(403).json({
                message: 'You do not have permission to access this resource'
            });
        }
    };
};

// Define a route to register a new user
app.post('/register', async (req, res) => {
    // Get the username, password, and role from the request body
    const { username, password, role } = req.body;

    // Validate the input
    if (!username || !password || !role) {
        return res.status(400).json({
            message: 'Username, password, and role are required'
        });
    }

    try {
        // Check if the username already exists
        const existingUser = await User.findOne({ username });

        if (existingUser) {
            return res.status(400).json({
                message: 'Username already taken'
            });
        }

        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user with the hashed password and the role
        const newUser = new User({
            username,
            password: hashedPassword,
            role
        });

        // Save the user to the database
        await newUser.save();

        // Generate a jwt token for the user
        const token = generateToken(newUser);

        // Return the token in the response
        return res.status(201).json({
            token
        });
    } catch (err) {
        // If there is an error, return 500 internal server error response
        return res.status(500).json({
            message: 'Something went wrong'
        });
    }
});

// Define a route to login an existing user
app.post('/login', async (req, res) => {
    // Get the username and password from the request body
    const { username, password } = req.body;

    // Validate the input
    if (!username || !password) {
        return res.status(400).json({
            message: 'Username and password are required'
        });
    }

    try {
        // Find the user by username
        const user = await User.findOne({ username });

        // Check if the user exists
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            });
        }

        // Compare the password with the hashed password
        const isMatch = await bcrypt.compare(password, user.password);

        // Check if the password is correct
        if (!isMatch) {
            return res.status(401).json({
                message: 'Wrong password'
            });
        }

        // Generate a jwt token for the user
        const token = generateToken(user);

        // Return the token in the response
        return res.status(200).json({
            token
        });
    } catch (err) {
        // If there is an error, return 500 internal server error response
        return res.status(500).json({
            message: 'Something went wrong'
        });
    }
});

// Define a route to get the current user profile
app.get('/profile', verifyToken, (req, res) => {
    // Get the user from the request object
    const user = req.user;

    // Return the user data in the response
    return res.status(200).json({
        id: user.id,
        username: user.username,
        role: user.role
    });
});

// Define a route to get all users (only for admin role)
app.get('/users', verifyToken, checkRole('admin'), async (req, res) => {
    try {
        // Find all users from the database
        const users = await User.find();

        // Return the users data in the response
        return res.status(200).json(users);
    } catch (err) {
        // If there is an error, return 500 internal server error response
        return res.status(500).json({
            message: 'Something went wrong'
        });
    }
});

// Start the server on port 3000
app.listen(3000, () => {
    console.log('Server listening on port 3000');
});
