// server.js

require('dotenv').config(); // Memuat variabel lingkungan dari .env
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const MySQLStore = require("express-mysql-session")(session);
const { body, validationResult } = require("express-validator");

const app = express();
app.get("/", (req, res) => {
  res.send("Selamat datang di API Worthbuyam");
});
// Gunakan Helmet untuk mengamankan header HTTP
app.use(helmet());

// Konfigurasi CORS (pastikan CLIENT_URL didefinisikan di environment)
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  })
);

// Parsing JSON dan cookie
app.use(express.json());
app.use(cookieParser());

// Buat connection pool dengan kredensial dari environment
const pool = mysql.createPool({
  host: process.env.DB_HOST || "sq21z.h.filess.io",
  user: process.env.DB_USER || "myapp_worthbuyam",
  port: process.env.DB_PORT || "3307",
  password: process.env.DB_PASSWORD || "3d8d4b4dbc719587f9089f082d29c1d9a464097f",
  database: process.env.DB_NAME || "myapp_worthbuyam",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Verifikasi koneksi database
pool.getConnection((err, connection) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to MySQL database!");
    connection.release();
  }
});

// Buat session store menggunakan MySQL
const sessionStore = new MySQLStore({}, pool.promise());

// Konfigurasi sesi
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your_secret_key_here", // Gunakan secret yang kuat dan simpan di environment
    resave: false,
    saveUninitialized: false,
    store: sessionStore, // Menggunakan MySQL session store
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Hanya true bila menggunakan HTTPS di produksi
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      maxAge: 24 * 60 * 60 * 1000, // 1 hari
    },
  })
);

// Rate limiter untuk endpoint autentikasi guna mencegah brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // Batas maksimal 100 request per IP dalam window ini
  message: "Terlalu banyak permintaan dari IP ini, silakan coba lagi nanti.",
});

// Terapkan rate limiter pada endpoint login, register, dan forgot-password
app.use(["/login", "/register", "/forgot-password"], authLimiter);

// Fungsi utilitas untuk menangani error query
function handleQueryError(err, res, defaultMessage) {
  console.error(defaultMessage, err);
  // Untuk produksi, hindari menampilkan detail error
  const message =
    process.env.NODE_ENV === "production"
      ? defaultMessage
      : `${defaultMessage}: ${err.message}`;
  return res.status(500).json({ success: false, message });
}

// ----------------------
// Endpoint API
// ----------------------

// API LOGIN: Autentikasi pengguna dan simpan data sesi
app.post(
  "/login",
  [
    body("email").isEmail().withMessage("Email tidak valid"),
    body("password").notEmpty().withMessage("Password diperlukan"),
  ],
  async (req, res) => {
    // Cek validasi input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, errors: errors.array() });
    }

    const { email, password } = req.body;

    pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          return handleQueryError(err, res, "Error saat login");
        }

        if (results.length === 0) {
          return res
            .status(401)
            .json({ success: false, message: "User dengan email tersebut tidak ditemukan" });
        }

        const user = results[0];
        try {
          const isPasswordValid = await bcrypt.compare(password, user.password);
          if (!isPasswordValid) {
            return res
              .status(401)
              .json({ success: false, message: "Password tidak valid" });
          }
        } catch (error) {
          return handleQueryError(error, res, "Error saat membandingkan password");
        }

        // Simpan data pengguna di sesi
        req.session.user = { id: user.id, name: user.name, email: user.email };
        return res.json({
          success: true,
          message: "Login berhasil",
          user: req.session.user,
        });
      }
    );
  }
);

// API LOGOUT: Hapus sesi pengguna dan cookie
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error saat logout:", err);
      return res
        .status(500)
        .json({ success: false, message: "Logout gagal" });
    }
    res.clearCookie("connect.sid");
    return res.json({ success: true, message: "Logout berhasil" });
  });
});

// API CEK STATUS LOGIN: Periksa apakah pengguna sudah terautentikasi
app.get("/auth", (req, res) => {
  if (req.session.user) {
    return res.json({ isAuthenticated: true, user: req.session.user });
  }
  return res.json({ isAuthenticated: false });
});

// API REGISTER: Daftarkan pengguna baru dengan validasi input
app.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Nama diperlukan"),
    body("email").isEmail().withMessage("Email tidak valid"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password harus minimal 6 karakter"),
  ],
  async (req, res) => {
    // Cek validasi input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, errors: errors.array() });
    }

    const { name, email, password } = req.body;

    pool.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
      if (err) {
        return handleQueryError(err, res, "Error saat pengecekan user");
      }
      if (results.length > 0) {
        return res
          .status(409)
          .json({ success: false, message: "Email sudah digunakan" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        pool.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [name, email, hashedPassword],
          (err, result) => {
            if (err) {
              if (err.code === "ER_DUP_ENTRY") {
                return res
                  .status(409)
                  .json({ success: false, message: "Email sudah digunakan" });
              }
              return handleQueryError(err, res, "Error saat registrasi");
            }
            return res.json({
              success: true,
              message: "Registrasi berhasil",
            });
          }
        );
      } catch (error) {
        console.error("Error saat hashing password:", error);
        return res
          .status(500)
          .json({ success: false, message: "Internal server error" });
      }
    });
  }
);

// API FORGOT PASSWORD: Proses permintaan reset password
app.post(
  "/forgot-password",
  [body("email").isEmail().withMessage("Email tidak valid")],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, errors: errors.array() });
    }

    const { email } = req.body;

    pool.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) {
        return handleQueryError(err, res, "Error saat request reset password");
      }
      if (results.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User dengan email tersebut tidak ditemukan" });
      }

      // Pada implementasi nyata:
      // 1. Buat token reset password.
      // 2. Simpan token dengan masa berlaku ke database.
      // 3. Kirim email ke pengguna berisi link reset password.
      // Untuk demo, kembalikan pesan sukses:
      return res.json({
        success: true,
        message: "Instruksi reset password telah dikirim ke email Anda.",
      });
    });
  }
);
// Endpoint /auth: Mengecek status login pengguna
app.get("/auth", (req, res) => {
  if (req.session && req.session.user) {
    return res.status(200).json({
      isAuthenticated: true,
      user: req.session.user, // kirim data user jika diperlukan
    });
  }
  return res.status(200).json({ isAuthenticated: false });
});
// ----------------------
// Menjalankan Server
// ----------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
