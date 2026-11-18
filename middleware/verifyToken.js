
const jwt = require("jsonwebtoken");
const db = require("../db");

const JWT_SECRET = process.env.JWT_SECRET;

async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Token tidak ditemukan",
    });
  }

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Format token salah",
    });
  }

  const token = authHeader.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      message: "Token tidak ditemukan",
    });
  }

  let decoded;

  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Token expired",
      });
    }

    return res.status(401).json({
      message: "Token tidak valid",
    });
  }

  if (!decoded.id || !decoded.sid) {
    return res.status(401).json({
      message: "Sesi tidak valid",
    });
  }

  try {
    const [rows] = await db.query(
      `SELECT id, name, email, role, is_active, refresh_token
             FROM users
             WHERE id = ?`,
      [decoded.id]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        message: "Sesi tidak valid",
      });
    }

    const user = rows[0];

    if (
      Number(user.is_active) !== 1 ||
      !user.refresh_token ||
      user.refresh_token !== decoded.sid
    ) {
      return res.status(401).json({
        message: "Sesi tidak valid",
      });
    }

    req.user = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      sid: decoded.sid,
    };

    return next();

  } catch (err) {
    console.error("AUTH SESSION CHECK ERROR:", err);

    return res.status(500).json({
      message: "Gagal memverifikasi sesi",
    });
  }
}

module.exports = verifyToken;
