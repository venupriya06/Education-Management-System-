
const jwt = require('jsonwebtoken');

module.exports = function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;

    // Check whether the token is provided
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            message: 'Authentication token required'
        });
    }

    // Extract token
    const token = authHeader.split(' ')[1];

    // Check JWT configuration
    if (!process.env.JWT_SECRET) {
        return res.status(500).json({
            message: 'JWT configuration error'
        });
    }

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach student ID to request
        if (!decoded.id) {
            return res.status(401).json({
                message: 'Invalid token payload'
            });
        }

        req.studentId = decoded.id;

        next();

    } catch (error) {
        return res.status(401).json({
            message: 'Invalid or expired token'
        });
    }
};
