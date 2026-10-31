const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },

    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },

    password: {
        type: String,
        required: true,
        minlength: 8
    },

    phone: {
        type: String,
        default: '',
        match: [/^[6-9]\d{9}$/, 'Enter a valid 10-digit Indian mobile number']
    }

}, { timestamps: true });

module.exports = mongoose.model('Student', studentSchema);