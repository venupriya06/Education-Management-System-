
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Student = require('../models/Student');

const router = express.Router();

// Student Signup
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: 'All fields are required'
            });
        }

        const existingStudent = await Student.findOne({ email });

        if (existingStudent) {
            return res.status(409).json({
                message: 'Email already registered'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const student = await Student.create({
            name,
            email,
            password: hashedPassword
        });

        res.status(201).json({
            message: 'Signup successful',
            student: {
                id: student._id,
                name: student.name,
                email: student.email
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Signup failed' });
    }
});

// Student Sign-in
router.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        const student = await Student.findOne({ email });

        if (!student || !(await bcrypt.compare(password || '', student.password))) {
            return res.status(401).json({
                message: 'Invalid email or password'
            });
        }

        const token = jwt.sign(
            { id: student._id },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({
            message: 'Sign-in successful',
            token
        });
    } catch (error) {
        res.status(500).json({ message: 'Sign-in failed' });
    }
});


const authMiddleware = require('../middleware/authMiddleware');

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

        res.json({
            message: 'Profile fetched successfully',
            student
        });
    } catch (error) {
        res.status(500).json({
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
            if (typeof phone !== 'string') {
                return res.status(400).json({
                    message: 'Phone must be a string'
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
            { new: true, runValidators: true }
        ).select('-password');

        if (!student) {
            return res.status(404).json({
                message: 'Student not found'
            });
        }

        res.json({
            message: 'Profile updated successfully',
            student
        });
    } catch (error) {
        res.status(500).json({
            message: 'Failed to update profile'
        });
    }
});

// Logout
router.post('/logout', authMiddleware, (req, res) => {
    res.json({
        message: 'Logout successful. Please delete your token on the client.'
    });
});


module.exports = router;
