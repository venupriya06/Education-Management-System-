
require('dotenv').config();

const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');

const app = express();

app.use(express.json());

// Homepage
app.get('/', (req, res) => {
    res.send('Education Management System is running');
});

// Authentication routes
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;

async function startServer() {
    await connectDB();

    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

startServer();
