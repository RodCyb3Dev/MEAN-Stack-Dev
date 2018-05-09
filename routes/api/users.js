const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');

// client Secret Key
const keys = require('../../config/keys');

// Input Validator
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');

// Load User Model
const User = require('../../models/User');

router.get('/test', (req, res) => res.json({msg: "Users Works"}));

// @route Get api/users/register
// @desc Register user
// @access Public
router.post('/register', (req, res) => {
    const { errors, isValid } = validateRegisterInput(req.body);

    // Check Validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    User.findOne({ email: req.body.email }).then(user => {
        if(user) {
            errors.email = 'Email already exists';
            return res.status(400).json(errors);
        } else {
            const avatar = gravatar.url(req.body.email, {
                size: '200', //Size
                rating: 'pg', // Rating
                default: 'mm' // Default
            });
            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                avatar,
                password: req.body.password
            });
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if(err) throw err;
                    newUser.password = hash;
                    newUser.save()
                        .then(user => res.json(user))
                        .catch(err => console.log(err));
                });
            });
        }
    });
});

// @route Get api/users/login
// @desc Login User via Returning Token (JWT)
// @access Public

router.post('/login', (req, res) => {
    const { errors, isValid } = validateLoginInput(req.body);

    // Check Validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;

    // Find User by Email
    User.findOne({ email }).then(user => {
        // Check for User
        if(!user) {
            errors.email = 'User not found';
            return res.status(404).json(errors);
        }
        // Check for Password
        bcrypt.compare(password, user.password).then(isMatch => {
            if (isMatch) {
                // User Matched
                const payload = { id: user.id, name: user.name, avatar: user.avatar } // Create JWT Payload

                // Sign Token
                jwt.sign(payload, keys.clientSecretKey, { expiresIn: 3600 }, (err, token) => {
                    res.json({
                        success: true,
                        token: 'Bearer ' + token
                    });
                });
            } else {
                return res.status(400).json({password: 'Password incorrect'});
            }
        });
    });
});

// @route Get api/users/Current
// @desc Returning Current
// @access Private
router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        avatar: req.user.avatar
    });
});

module.exports = router;