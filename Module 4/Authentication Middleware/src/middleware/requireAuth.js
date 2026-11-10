
const jwt = require("jsonwebtoken");

module.exports = function requireAuth(req, res, next) {
    // Read Authorization header
    const authHeader = req.headers.authorization;

    // Extract Bearer token using strict regex
    const match = authHeader?.match(/^Bearer ([^\s]+)$/i);

    // Return 401 if token is missing or invalid format
    if (!match) {
        return res.status(401).json({
            error: {
                code: "AUTH_REQUIRED",
                message: "Authentication required"
            }
        });
    }

    const token = match[1];

    try {
        // Verify JWT
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET,
            { algorithms: ["HS256"] }
        );

        // Attach payload to request
        req.user = decoded;

        // Continue to route
        next();

    } catch (error) {
        return res.status(401).json({
            error: {
                code: "AUTH_REQUIRED",
                message: "Authentication required"
            }
        });
    }
};
