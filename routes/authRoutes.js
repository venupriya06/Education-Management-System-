
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Student = require('../models/student');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// Student Signup
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password, phone } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: 'Name, email and password are required'
            });
        }

        if (
            typeof name !== 'string' ||
            typeof email !== 'string' ||
            typeof password !== 'string'
        ) {
            return res.status(400).json({
                message: 'Invalid input format'
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();

        if (!cleanName) {
            return res.status(400).json({
                message: 'Name cannot be empty'
            });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
            return res.status(400).json({
                message: 'Enter a valid email address'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: 'Password must be at least 8 characters'
            });
        }

        if (phone !== undefined && phone !== '') {
            if (
                typeof phone !== 'string' ||
                !/^[6-9]\d{9}$/.test(phone.trim())
            ) {
                return res.status(400).json({
                    message: 'Enter a valid 10-digit Indian mobile number'
                });
            }
        }

        const existingStudent = await Student.findOne({
            email: cleanEmail
        });

        if (existingStudent) {
            return res.status(409).json({
                message: 'Email already registered'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const student = await Student.create({
            name: cleanName,
            email: cleanEmail,
            password: hashedPassword,
            phone: phone ? phone.trim() : ''
        });

        return res.status(201).json({
            message: 'Signup successful',
            student: {
                id: student._id,
                name: student.name,
                email: student.email,
                phone: student.phone
            }
        });

    } catch (error) {
        console.error('Signup error:', error.message);

        if (error.code === 11000) {
            return res.status(409).json({
                message: 'Email already registered'
            });
        }

        return res.status(500).json({
            message: 'Signup failed'
        });
    }
});


// Student Sign-in
router.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== 'string' ||
            typeof password !== 'string' ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                message: 'Email and password are required'
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        const student = await Student.findOne({
            email: cleanEmail
        });

        if (!student || !(await bcrypt.compare(password, student.password))) {
            return res.status(401).json({
                message: 'Invalid email or password'
            });
        }

        if (!process.env.JWT_SECRET) {
            console.error('JWT_SECRET is missing');

            return res.status(500).json({
                message: 'Authentication configuration error'
            });
        }

        const token = jwt.sign(
            { id: student._id.toString() },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        return res.status(200).json({
            message: 'Sign-in successful',
            token
        });

    } catch (error) {
        console.error('Signin error:', error.message);

        return res.status(500).json({
            message: 'Sign-in failed'
        });
    }
});


// Get logged-in student's profile
router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const student = await Student.findById(req.studentId)
            .select('-password');

        if (!student) {
            return res.status(404).json({
                message: 'Student not found'
            });
        }

        return res.status(200).json({
            message: 'Profile fetched successfully',
            student
        });

    } catch (error) {
        console.error('Profile error:', error.message);

        return res.status(500).json({
            message: 'Failed to fetch profile'
        });
    }
});


// Update logged-in student's profile
router.put('/update-profile', authMiddleware, async (req, res) => {
    try {
        const { name, phone } = req.body;

        const updates = {};

        if (name !== undefined) {
            if (typeof name !== 'string' || !name.trim()) {
                return res.status(400).json({
                    message: 'Name cannot be empty'
                });
            }

            updates.name = name.trim();
        }

        if (phone !== undefined) {
            if (
                typeof phone !== 'string' ||
                (phone.trim() !== '' && !/^[6-9]\d{9}$/.test(phone.trim()))
            ) {
                return res.status(400).json({
                    message: 'Enter a valid 10-digit Indian mobile number'
                });
            }

            updates.phone = phone.trim();
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({
                message: 'Provide name or phone to update'
            });
        }

        const student = await Student.findByIdAndUpdate(
            req.studentId,
            { $set: updates },
            {
                new: true,
                runValidators: true
            }
        ).select('-password');

        if (!student) {
            return res.status(404).json({
                message: 'Student not found'
            });
        }

        return res.status(200).json({
            message: 'Profile updated successfully',
            student
        });

    } catch (error) {
        console.error('Update profile error:', error.message);

        return res.status(500).json({
            message: 'Failed to update profile'
        });
    }
});


// Student Logout
router.post('/logout', authMiddleware, (req, res) => {
    return res.status(200).json({
        message: 'Logout successful. Please delete your token on the client.'
    });
});


module.exports = router;
